use crate::ui::app::App;
use crossterm::event::{Event, KeyCode};

pub async fn handle_events(app: &mut App) -> anyhow::Result<bool> {
    if crossterm::event::poll(std::time::Duration::from_millis(50))? {
        if let Event::Key(key_event) = crossterm::event::read()? {
            match key_event.code {
                KeyCode::Char('Q') | KeyCode::Char('q') => return Ok(true),
                _ => {}
            }
        }
    }
    app.update().await;
    Ok(false)
}
