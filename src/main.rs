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
use crate::bpf_user::{handler::BpfHandler, loader::BpfLoader, maps::BpfMaps};
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
    /// Run the firewall with interactive TUI
    Run {
        /// Network interface to attach the XDP program to
        interface: String,
    },
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
        Commands::Run { interface } => {
            run_tui(&interface).await?;
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

async fn run_tui(interface: &str) -> Result<()> {
    let (tx_cmd, rx_cmd) = mpsc::channel(32); // Commands: UI -> BPF
    let (tx_log, rx_log) = mpsc::channel(32); // Logs: BPF -> UI
    let bpf_loader = BpfLoader::new(interface)?;
    
    // Load existing rules from eBPF map before moving loader
    let existing_rules = bpf_loader.get_all_rules().unwrap_or_else(|e| {
        log::warn!("Failed to load existing rules: {}", e);
        Vec::new()
    });
    
    let tx_log_clone = tx_log.clone();
    let handler_handle = std::thread::spawn(move || {
        let mut bpf_handler = BpfHandler::new(bpf_loader, rx_cmd, tx_log_clone);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            bpf_handler.run().await;
        });
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

    if app.unload_requested {
        if let Err(e) = handler_handle.join() {
            log::error!("BPF handler thread panicked during unload: {:?}", e);
        }
    } else {
        drop(handler_handle);
    }
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
    if !Path::new(&format!("{}/rules_map", FIREBEE_DIR)).exists() {
        anyhow::bail!("No active firebee instance found. Maps are not pinned at {}. Run 'firebee run <interface>' or add rules with --attach flag first.", FIREBEE_DIR);
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