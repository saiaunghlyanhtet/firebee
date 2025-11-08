use anyhow::Result;
use crossterm::{
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{prelude::*};
use std::io;
use tokio::sync::mpsc;
use crate::bpf_user::{handler::BpfHandler, loader::BpfLoader};
use crate::ui::{app::App, events::handle_events, widgets::render_ui};

mod bpf_user;
mod models;
mod ui;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let (tx_cmd, rx_cmd) = mpsc::channel(32); // Commands: UI -> BPF
    let (tx_log, rx_log) = mpsc::channel(32); // Logs: BPF -> UI
    let bpf_loader = BpfLoader::new("wlp2s0")?; // Use the active wireless interface
    
    // Load existing rules from eBPF map before moving loader
    let existing_rules = bpf_loader.get_all_rules().unwrap_or_else(|e| {
        log::warn!("Failed to load existing rules: {}", e);
        Vec::new()
    });
    
    let tx_log_clone = tx_log.clone();
    std::thread::spawn(move || {
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
    Ok(())
}