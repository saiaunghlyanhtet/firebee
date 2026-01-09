use anyhow::Result;
use libbpf_rs::{ObjectBuilder, Link, MapCore};
use std::fs;
use std::path::Path;
use crate::models::rule::{Action, Rule};
use std::net::Ipv4Addr;

pub struct BpfLoader {
    pub bpf_object: libbpf_rs::Object,
    pub links: Vec<Link>,
    pub interface: String,
}

const BPF_FS: &str = "/sys/fs/bpf";
const FIREBEE_DIR: &str = "/sys/fs/bpf/firebee";

impl BpfLoader {
    pub fn new(iface: &str) -> Result<Self> {
        Self::ensure_bpf_fs()?;
        
        Self::create_pin_directory()?;
        
        if !fs::metadata("target/bpf/firebee.bpf.o").is_ok() {
            return Err(anyhow::anyhow!("BPF object file not found. Run `cargo libbpf build` first."));
        }
        
        let reuse_maps = Path::new(&format!("{}/rules_map", FIREBEE_DIR)).exists() 
            && Path::new(&format!("{}/log_events", FIREBEE_DIR)).exists();
        
        if reuse_maps {
            log::info!("Found existing pinned maps, will reuse them");
        } else {
            log::info!("No existing pinned maps found, will create new ones");
        }
        
        let mut builder = ObjectBuilder::default();
        
        let mut open_obj = builder.open_file("target/bpf/firebee.bpf.o")?;
        
        // If we're reusing maps, set them to be reused
        if reuse_maps {
            for mut map in open_obj.maps_mut() {
                let map_name = map.name().to_string_lossy().to_string();
                let pin_path = format!("{}/{}", FIREBEE_DIR, map_name);
                if Path::new(&pin_path).exists() {
                    log::info!("Reusing pinned map: {}", map_name);
                    if let Err(e) = map.set_pin_path(&pin_path) {
                        log::warn!("Failed to set pin path for map {}: {}", map_name, e);
                    }
                }
            }
        }
        
        let mut obj = open_obj.load()?;
        
        for mut map in obj.maps_mut() {
            let map_name = map.name().to_string_lossy().to_string();
            let pin_path = format!("{}/{}", FIREBEE_DIR, map_name);
            
            if !reuse_maps {
                match map.pin(&pin_path) {
                    Ok(_) => log::info!("Pinned map '{}' to {}", map_name, pin_path),
                    Err(e) => {
                        log::warn!("Could not pin map '{}': {} (may already be pinned)", map_name, e);
                    }
                }
            }
        }
        
        let mut prog = None;
        for p in obj.progs_mut() {
            if p.name().to_string_lossy() == "xdp_firewall" {
                prog = Some(p);
                break;
            }
        }
        
        let mut prog = prog.ok_or_else(|| anyhow::anyhow!("xdp_firewall program not found"))?;
        
        // Pin the program for persistence
        let prog_pin_path = format!("{}/xdp_firewall", FIREBEE_DIR);
        match prog.pin(&prog_pin_path) {
            Ok(_) => log::info!("Pinned program to {}", prog_pin_path),
            Err(e) => log::warn!("Could not pin program: {} (may already be pinned)", e),
        }
        
        // Attach XDP program to interface
        let mut link = prog.attach_xdp(Self::get_ifindex(iface)?)?;
        log::info!("Attached XDP program to interface {}", iface);
        
        // Pin the link to keep XDP attached even after process exits
        let link_pin_path = format!("{}/xdp_link", FIREBEE_DIR);
        match link.pin(&link_pin_path) {
            Ok(_) => log::info!("Pinned XDP link to {}", link_pin_path),
            Err(e) => log::warn!("Could not pin link: {} (may already be pinned)", e),
        }
        
        let links = vec![link];
        
        Ok(BpfLoader { 
            bpf_object: obj,
            links,
            interface: iface.to_string(),
        })
    }
    
    pub fn get_all_rules(&self) -> Result<Vec<Rule>> {
        let mut rules = Vec::new();
        
        let rules_map = self.bpf_object.maps().find(|m| {
            m.name().to_string_lossy() == "rules_map"
        }).ok_or_else(|| anyhow::anyhow!("rules_map not found"))?;
        
        for key in rules_map.keys() {
            if let Some(value) = rules_map.lookup(&key, libbpf_rs::MapFlags::ANY)? {
                if key.len() >= std::mem::size_of::<crate::bpf_user::maps::RuleKey>() {
                    let rule_key = unsafe {
                        std::ptr::read(key.as_ptr() as *const crate::bpf_user::maps::RuleKey)
                    };
                    
                    let ip = Ipv4Addr::from(rule_key.src_ip);
                    
                    if !value.is_empty() {
                        let action = if value[0] == 0 {
                            Action::Drop
                        } else {
                            Action::Allow
                        };
                        
                        let protocol = crate::models::rule::Protocol::from_u8(rule_key.protocol);
                        let subnet_mask = if rule_key.subnet_mask == 0xFFFFFFFF {
                            None
                        } else if rule_key.subnet_mask == 0 {
                            Some(0)
                        } else {
                            Some(rule_key.subnet_mask.count_ones() as u8)
                        };
                        
                        rules.push(Rule {
                            ip,
                            subnet_mask,
                            action,
                            protocol,
                            src_port: if rule_key.src_port == 0 { None } else { Some(rule_key.src_port) },
                            dst_port: if rule_key.dst_port == 0 { None } else { Some(rule_key.dst_port) },
                        });
                    }
                }
            }
        }
        
        log::info!("Loaded {} existing rules from eBPF map", rules.len());
        Ok(rules)
    }
    
    pub fn unload(iface: &str) -> Result<()> {
        log::info!("Unloading BPF program and unpinning maps");
        
        // Note: XDP program should already be detached by dropping the Link objects
        // We'll try to detach again just to be safe, in case it wasn't
        log::info!("Ensuring XDP program is detached from interface {}", iface);
        let detach_status = std::process::Command::new("ip")
            .args(["link", "set", "dev", iface, "xdp", "off"])
            .status();
            
        match detach_status {
            Ok(status) if status.success() => {
                log::info!("Successfully detached XDP program from {}", iface);
            }
            Ok(_) => {
                log::debug!("XDP program already detached from {}", iface);
            }
            Err(e) => {
                log::warn!("Error running ip command: {}", e);
            }
        }
        
        // Give kernel a moment to clean up
        std::thread::sleep(std::time::Duration::from_millis(100));

        if Path::new(FIREBEE_DIR).exists() {
            if let Err(e) = fs::read_dir(FIREBEE_DIR).map(|entries| {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                        log::info!("Removing pinned object: {}", name);
                    }

                    let remove_result = if path.is_dir() {
                        fs::remove_dir_all(&path)
                    } else {
                        fs::remove_file(&path)
                    };

                    if let Err(err) = remove_result {
                        log::warn!("Failed to remove pinned object {:?}: {}", path, err);
                    }
                }
            }) {
                log::warn!("Failed to iterate pinned directory {}: {}", FIREBEE_DIR, e);
            }

            match fs::remove_dir(FIREBEE_DIR) {
                Ok(_) => log::info!("Removed BPF directory: {}", FIREBEE_DIR),
                Err(e) => log::warn!("Failed to remove BPF directory: {}", e),
            }
        }
        
        log::info!("BPF program and maps unloaded successfully");
        Ok(())
    }
    
    // Get network interface index
    fn get_ifindex(iface: &str) -> Result<i32> {
        let output = std::process::Command::new("ip")
            .args(["link", "show", iface])
            .output()?;
        
        let stdout = String::from_utf8(output.stdout)?;
        let first_line = stdout.lines().next()
            .ok_or_else(|| anyhow::anyhow!("No output from ip link show"))?;
        
        // Parse "2: wlp2s0: ..." to get the index
        let index_str = first_line.split(':').next()
            .ok_or_else(|| anyhow::anyhow!("Could not parse interface index"))?
            .trim();
        
        index_str.parse::<i32>()
            .map_err(|e| anyhow::anyhow!("Could not parse index as i32: {}", e))
    }
    
    // Create directory for pinned objects
    fn create_pin_directory() -> Result<()> {
        if !Path::new(FIREBEE_DIR).exists() {
            log::info!("Creating directory for pinned BPF objects: {}", FIREBEE_DIR);
            fs::create_dir_all(FIREBEE_DIR)?;
        }
        Ok(())
    }
    
        
    fn ensure_bpf_fs() -> Result<()> {
        let bpf_path = Path::new(BPF_FS);
        
        if !bpf_path.exists() {
            log::info!("BPF filesystem not mounted, trying to mount it");
            
            fs::create_dir_all(BPF_FS)?;
            
            let mount_status = std::process::Command::new("mount")
                .args(["-t", "bpf", "bpffs", BPF_FS])
                .status()?;
                
            if !mount_status.success() {
                return Err(anyhow::anyhow!("Failed to mount BPF filesystem. Try running: sudo mount -t bpf bpffs {}", BPF_FS));
            }
            
            log::info!("Successfully mounted BPF filesystem");
        } else {
            let mount_output = std::process::Command::new("mount")
                .output()
                .ok()
                .and_then(|output| String::from_utf8(output.stdout).ok());
                
            if let Some(output) = mount_output {
                if !output.contains(&format!("on {} type bpf", BPF_FS)) {
                    log::info!("BPF filesystem directory exists but not mounted, mounting it");
                    
                    let mount_status = std::process::Command::new("mount")
                        .args(["-t", "bpf", "bpffs", BPF_FS])
                        .status()?;
                        
                    if !mount_status.success() {
                        return Err(anyhow::anyhow!("Failed to mount BPF filesystem. Try running: sudo mount -t bpf bpffs {}", BPF_FS));
                    }
                    
                    log::info!("Successfully mounted BPF filesystem");
                } else {
                    log::info!("BPF filesystem is already mounted");
                }
            }
        }
        
        Ok(())
    }
}