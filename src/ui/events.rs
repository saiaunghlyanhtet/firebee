use crossterm::event::{Event, KeyCode};
use crate::ui::app::{App};
use crate::models::rule::Action;

pub async fn handle_events(app: &mut App) -> anyhow::Result<bool> {
    if crossterm::event::poll(std::time::Duration::from_millis(50))? {
        if let Event::Key(key_event) = crossterm::event::read()? {
            if app.confirm_unload {
                // Handle confirmation dialog
                match key_event.code {
                    KeyCode::Char('Y') | KeyCode::Char('y') => {
                        if app.unload().await {
                            return Ok(true); // Exit the application once unload completes
                        } else {
                            log::error!("Failed to send unload command");
                            app.confirm_unload = false;
                        }
                    }
                    KeyCode::Char('N') | KeyCode::Char('n') | KeyCode::Esc => {
                        app.confirm_unload = false;
                    }
                    _ => {}
                }
            } else if app.input_mode {
                match key_event.code {
                    KeyCode::Enter => {
                        let action = Action::Drop;
                        let input_copy = app.input.clone();
                        let _ = app.add_rule(&input_copy, action).await;
                        app.input.clear();
                        app.input_mode = false;
                    }
                    KeyCode::Char(c) => {
                        app.input.push(c);
                    }
                    KeyCode::Backspace => {
                        app.input.pop();
                    }
                    KeyCode::Esc => {
                        app.input.clear();
                        app.input_mode = false;
                    }
                    _ => {}
                }
            } else {
                match key_event.code {
                    KeyCode::Char('Q') => return Ok(true),
                    KeyCode::Char('A') => {
                        app.input_mode = true;
                    }
                    KeyCode::Char('U') => {
                        app.confirm_unload = true;
                    }
                    _ => {}
                }
            }
        }
    }
    app.update().await;
    Ok(false)
}
