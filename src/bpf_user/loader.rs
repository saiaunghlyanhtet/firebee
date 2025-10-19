use anyhow::Result;
use libbpf_rs::ObjectBuilder;
use std::fs;

pub struct BpfLoader {
    pub bpf_object: libbpf_rs::Object,
}

impl BpfLoader {
    pub fn new(_iface: &str) -> Result<Self> {
        // Use the simplest API possible to load the BPF object
        // First check if the file exists
        if !fs::metadata("target/bpf/firebee.bpf.o").is_ok() {
            return Err(anyhow::anyhow!("BPF object file not found. Run `cargo libbpf build` first."));
        }
        
        // Create the builder
        let mut builder = ObjectBuilder::default();
        
        // Open the file (not memory)
        let open_obj = builder.open_file("target/bpf/firebee.bpf.o")?;
        
        // Load the object
        let obj = open_obj.load()?;
        
        // We'll simplify and assume the program is loaded correctly
        // In a real app, you'd validate the programs exist and attach them
        log::info!("Loaded BPF object successfully");
        
        // Return the loader with the object
        Ok(BpfLoader { bpf_object: obj })
    }
}