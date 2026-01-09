use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use crossterm::{
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{prelude::*};
use std::io;
use std::path::PathBuf;
use once_cell::sync::OnceCell;
use tokio::sync::mpsc;
use crate::bpf_user::{loader::BpfLoader, maps::BpfMaps};
use crate::ui::{app::App, events::handle_events, widgets::render_ui};
use crate::policy::{parse_policy_file, validate_policy};
use crate::state::RulesState;

mod bpf_user;
mod models;
mod policy;
mod state;
mod ui;

// Global singleton for the BPF object used by CLI commands
// This ensures we only create one instance and avoid memory leaks
static PINNED_BPF_OBJ: OnceCell<libbpf_rs::Object> = OnceCell::new();

#[derive(Parser)]
#[command(name = "firebee")]
#[command(about = "eBPF-based XDP firewall with TUI", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Clone, ValueEnum)]
enum OutputFormat {
    Yaml,
    Json,
}

#[derive(Subcommand)]
enum Commands {
    /// Attach and load the XDP firewall program
    Run {
        /// Network interface to attach the XDP program to
        interface: String,
        
        /// Optional policy file to load rules from
        #[arg(short, long)]
        policy: Option<PathBuf>,
    },
    /// Show the firewall TUI (interactive interface)
    Ui,
    /// Add rules from a policy file
    Add {
        /// Network interface (must already have firebee running or use with --attach)
        #[arg(short, long)]
        interface: Option<String>,
        
        /// Policy file containing rules to add
        #[arg(short, long)]
        policy: PathBuf,
        
        /// Attach to interface if not already attached
        #[arg(short, long)]
        attach: bool,
    },
    /// Get rule information
    Get {
        #[command(subcommand)]
        command: GetCommands,
    },
    /// Delete rule
    Delete {
        #[command(subcommand)]
        command: DeleteCommands,
    },
}

#[derive(Subcommand)]
enum GetCommands {
    /// Get rule(s) - shows all rules if name not provided
    Rule {
        /// Name of the rule to retrieve (optional - shows all if omitted)
        name: Option<String>,
        
        /// Output format
        #[arg(short, long, value_enum, default_value = "yaml")]
        output: OutputFormat,
    },
}

#[derive(Subcommand)]
enum DeleteCommands {
    /// Delete a rule by name
    Rule {
        /// Name of the rule to delete
        name: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Run { interface, policy } => {
            run_firewall(&interface, policy).await?;
        }
        Commands::Ui => {
            run_tui().await?;
        }
        Commands::Add { interface, policy, attach } => {
            add_rules_from_policy(interface, policy, attach).await?;
        }
        Commands::Get { command } => {
            match command {
                GetCommands::Rule { name, output } => {
                    get_rule(name.as_deref(), output)?;
                }
            }
        }
        Commands::Delete { command } => {
            match command {
                DeleteCommands::Rule { name } => {
                    delete_rule(&name).await?;
                }
            }
        }
    }

    Ok(())
}

async fn run_firewall(interface: &str, policy: Option<PathBuf>) -> Result<()> {
    println!("Attaching XDP firewall to interface: {}", interface);
    let _loader = BpfLoader::new(interface)?;
    println!("✓ XDP program attached to {}", interface);
    
    // Load rules from policy file if provided
    if let Some(policy_path) = policy {
        println!("\nLoading rules from policy file: {}", policy_path.display());
        
        let policy = parse_policy_file(&policy_path)?;
        validate_policy(&policy)?;
        println!("Policy validation passed!");
        
        let maps = open_pinned_maps()?;
        
        for policy_rule in &policy.rules {
            RulesState::add_rule(&maps, policy_rule)?;
            
            let rule = policy_rule.to_rule()?;
            let action = match rule.action {
                crate::models::rule::Action::Allow => "ALLOW",
                crate::models::rule::Action::Drop => "DROP",
            };
            
            println!("✓ Added rule '{}': {} -> {}", 
                policy_rule.name, 
                rule.ip,
                action
            );
        }
        
        println!("\nSuccessfully loaded {} rules!", policy.rules.len());
    }
    
    println!("\nXDP firewall is running. Use 'firebee ui' to view the TUI.");
    println!("The program will stay attached. Run 'firebee add' to add more rules.");
    
    // Keep the loader alive to prevent XDP detachment
    std::mem::forget(_loader);
    
    Ok(())
}

async fn run_tui() -> Result<()> {
    let (tx_cmd, _rx_cmd) = mpsc::channel(32); // Commands: UI -> BPF
    let (tx_log, rx_log) = mpsc::channel(32); // Logs: BPF -> UI
    
    // Load existing rules from BPF maps
    let maps = open_pinned_maps()?;
    let existing_rules = RulesState::list_rules(&maps).unwrap_or_else(|e| {
        log::warn!("Failed to load existing rules: {}", e);
        Vec::new()
    });
    
    // Start event reader thread to consume ring buffer events
    let tx_log_clone = tx_log.clone();
    let event_handle = std::thread::spawn(move || {
        use libbpf_rs::RingBufferBuilder;
        use std::net::Ipv4Addr;
        
        // Open maps inside the thread since they're not Send
        let maps = match open_pinned_maps() {
            Ok(m) => m,
            Err(e) => {
                log::error!("Failed to open maps in event thread: {}", e);
                return;
            }
        };
        
        let mut rb_builder = RingBufferBuilder::new();
        let log_tx = tx_log_clone;

        rb_builder
            .add(&maps.log_events, move |data| {
                if data.len() >= 8 {
                    let src_ip = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
                    let action = data[4];
                    let ip = Ipv4Addr::from(src_ip);
                    let msg = format!(
                        "Packet from {}: {}",
                        ip,
                        if action == 0 { "DROPPED" } else { "PASSED" }
                    );

                    let _ = log_tx.try_send(msg);
                }
                0
            })
            .expect("Failed to create ring buffer");

        let rb = rb_builder.build().expect("Failed to build ring buffer");

        loop {
            if let Err(e) = rb.poll(std::time::Duration::from_millis(100)) {
                log::error!("Ring buffer poll error: {}", e);
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        }
    });

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new(tx_cmd, rx_log, existing_rules);

    loop {
        terminal.draw(|f| render_ui::<CrosstermBackend<io::Stdout>>(f, &mut app))?;
        if handle_events(&mut app).await? {
            break; 
        }
    }

    // Cleanup
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    
    // Stop the event reader thread
    drop(event_handle);

    Ok(())
}

async fn add_rules_from_policy(
    interface: Option<String>,
    policy_path: PathBuf,
    attach: bool,
) -> Result<()> {
    println!("Reading policy file: {}", policy_path.display());
    
    // Parse and validate the policy file
    let policy = parse_policy_file(&policy_path)?;
    
    validate_policy(&policy)?;
    println!("Policy validation passed!");
    
    println!("Found {} rules to add", policy.rules.len());
    
    // If attach flag is set, load the BPF program
    let _loader = if attach {
        let iface = interface.ok_or_else(|| {
            anyhow::anyhow!("--interface required when using --attach")
        })?;
        println!("Attaching to interface: {}", iface);
        Some(BpfLoader::new(&iface)?)
    } else {
        None
    };
    
    // Access the BPF maps (either newly created or pinned)
    let maps = if _loader.is_some() {
        // If we just attached, the maps are newly created and pinned
        // We need to open them from the pinned location
        open_pinned_maps()?
    } else {
        // If not attaching, try to open existing pinned maps
        open_pinned_maps()?
    };
    
    for policy_rule in &policy.rules {
        RulesState::add_rule(&maps, policy_rule)?;
        
        let rule = policy_rule.to_rule()?;
        let action = match rule.action {
            crate::models::rule::Action::Allow => "ALLOW",
            crate::models::rule::Action::Drop => "DROP",
        };
        
        println!("✓ Added rule '{}': {} -> {}", 
            policy_rule.name, 
            rule.ip,
            action
        );
    }
    
    println!("\nSuccessfully added {} rules!", policy.rules.len());
    println!("Rules are now active in the eBPF firewall.");
    
    // Keep the loader alive if we attached
    // This prevents the XDP program from being detached
    if _loader.is_some() {
        println!("\nXDP program is attached and will remain active.");
        println!("The program will stay loaded even after this command exits.");
        std::mem::forget(_loader); // Intentionally leak to keep XDP attached
    }
    
    Ok(())
}

fn open_pinned_maps() -> Result<BpfMaps<'static>> {
    use std::path::Path;
    
    // Check if maps are pinned
    const FIREBEE_DIR: &str = "/sys/fs/bpf/firebee";
    let rules_map_path = format!("{}/rules_map", FIREBEE_DIR);
    
    if !Path::new(&rules_map_path).exists() {
        anyhow::bail!(
            "No active firebee instance found. Maps are not pinned at {}.\n\
            Run 'sudo firebee run <interface>' first, or add rules with --attach flag.\n\
            Note: If firebee is running, make sure to use 'sudo' for this command too.",
            FIREBEE_DIR
        );
    }
    
    // Get or initialize the singleton BPF object
    let obj = PINNED_BPF_OBJ.get_or_try_init(|| -> Result<libbpf_rs::Object> {
        // Open BPF object and reuse pinned maps
        let mut builder = libbpf_rs::ObjectBuilder::default();
        let mut open_obj = builder.open_file("target/bpf/firebee.bpf.o")
            .context("Failed to open BPF object file")?;
        
        // Set all maps to reuse pinned paths instead of creating new ones
        for mut map in open_obj.maps_mut() {
            let map_name = map.name().to_string_lossy().to_string();
            let pin_path = format!("{}/{}", FIREBEE_DIR, map_name);
            if Path::new(&pin_path).exists() {
                map.reuse_pinned_map(&pin_path)
                    .with_context(|| format!("Failed to reuse pinned map {}", map_name))?;
            }
        }
        
        open_obj.load()
            .context("Failed to load BPF object")
    })?;
    
    let maps = BpfMaps::new(obj);
    
    Ok(maps)
}

fn get_rule(name: Option<&str>, format: OutputFormat) -> Result<()> {
    // Access pinned BPF maps
    let maps = open_pinned_maps()?;
    
    match name {
        Some(rule_name) => {
            let rule = RulesState::get_rule(&maps, rule_name)?
                .ok_or_else(|| anyhow::anyhow!("Rule '{}' not found", rule_name))?;
            
            let output = match format {
                OutputFormat::Yaml => {
                    serde_yaml::to_string(&rule)
                        .context("Failed to serialize rule to YAML")?
                }
                OutputFormat::Json => {
                    serde_json::to_string_pretty(&rule)
                        .context("Failed to serialize rule to JSON")?
                }
            };
            
            println!("{}", output);
        }
        None => {
            // Get all rules
            let rules = RulesState::list_rules(&maps)?;
            
            if rules.is_empty() {
                println!("No rules found");
                return Ok(());
            }
            
            let output = match format {
                OutputFormat::Yaml => {
                    serde_yaml::to_string(&rules)
                        .context("Failed to serialize rules to YAML")?
                }
                OutputFormat::Json => {
                    serde_json::to_string_pretty(&rules)
                        .context("Failed to serialize rules to JSON")?
                }
            };
            
            println!("{}", output);
            println!("\nTotal rules: {}", rules.len());
        }
    }
    
    Ok(())
}

async fn delete_rule(name: &str) -> Result<()> {
    // Access pinned BPF maps
    let maps = open_pinned_maps()?;
    
    // Delete from BPF maps (both rules and metadata)
    let rule = RulesState::delete_rule(&maps, name)?
        .ok_or_else(|| anyhow::anyhow!("Rule '{}' not found", name))?;
    
    println!("✓ Deleted rule '{}'  (IP: {})", name, rule.ip);
    println!("Rule is now inactive in the eBPF firewall.");
    
    Ok(())
}