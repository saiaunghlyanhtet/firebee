use anyhow::Result;
use clap::{Parser, Subcommand};
use crossterm::{
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{prelude::*};
use std::io;
use std::path::PathBuf;
use tokio::sync::mpsc;
use crate::bpf_user::{handler::BpfHandler, loader::BpfLoader, maps::BpfMaps};
use crate::ui::{app::App, events::handle_events, widgets::render_ui};
use crate::policy::{parse_policy_file, validate_policy};

mod bpf_user;
mod models;
mod policy;
mod ui;

#[derive(Parser)]
#[command(name = "firebee")]
#[command(about = "eBPF-based XDP firewall with TUI", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
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
    
    // Convert policy rules to internal rules
    let mut rules = Vec::new();
    for policy_rule in &policy.rules {
        let rule = policy_rule.to_rule()?;
        rules.push((policy_rule.name.clone(), rule));
    }
    
    println!("Found {} rules to add", rules.len());
    
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
    
    // Access the existing BPF maps
    // We need to open the existing BPF object from the pinned maps
    let obj = libbpf_rs::ObjectBuilder::default()
        .open_file("target/bpf/firebee.bpf.o")?
        .load()?;
    
    let maps = BpfMaps::new(&obj);
    
    // Add each rule to the BPF maps
    for (name, rule) in &rules {
        let action = match rule.action {
            crate::models::rule::Action::Allow => 1,
            crate::models::rule::Action::Drop => 0,
        };
        
        maps.update_rule(rule.ip, action)?;
        println!("✓ Added rule '{}': {} -> {}", 
            name, 
            rule.ip,
            if action == 1 { "ALLOW" } else { "DROP" }
        );
    }
    
    println!("\nSuccessfully added {} rules!", rules.len());
    println!("Rules are now active in the eBPF firewall.");
    
    Ok(())
}