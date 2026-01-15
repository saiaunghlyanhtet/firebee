use crate::ui::app::App;
use ratatui::{prelude::*, text::ToText, widgets::*};

pub fn render_ui<B: Backend>(f: &mut Frame, app: &mut App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(50),
            Constraint::Percentage(45),
            Constraint::Length(3),
        ].as_ref())
        .split(f.area());

    let rules = app.rules.iter().map(|r| {
        let action = match r.action.to_lowercase().as_str() {
            "allow" => "Allow",
            "drop" => "Drop",
            _ => &r.action,
        };
        
        let protocol = r.protocol.to_uppercase();
        
        let direction = match r.direction.to_lowercase().as_str() {
            "ingress" | "in" => "In",
            "egress" | "out" => "Out",
            "both" => "Both",
            _ => &r.direction,
        };
        
        let ports = match (&r.src_port, &r.dst_port) {
            (Some(src), Some(dst)) => format!("{}:{}", src, dst),
            (Some(src), None) => format!("{}:*", src),
            (None, Some(dst)) => format!("*:{}", dst),
            (None, None) => "*".to_string(),
        };
        
        let description = r.description.as_deref().unwrap_or("-");
        
        // Format stats - get from app.rule_stats if available
        let (packets, bytes) = app.rule_stats.get(&r.name)
            .map(|(p, b)| (*p, *b))
            .unwrap_or((0, 0));
        
        let stats = if packets > 0 {
            format!("{} pkts / {}", format_number(packets), format_bytes(bytes))
        } else {
            "-".to_string()
        };
        
        Row::new(vec![
            r.name.clone(),
            r.ip.clone(),
            protocol.to_string(),
            direction.to_string(),
            ports,
            action.to_string(),
            stats,
            description.to_string(),
        ])
    });

    let rules_table = Table::new(
        rules,
        [
            Constraint::Percentage(11),  // Name
            Constraint::Percentage(14),  // IP/CIDR
            Constraint::Percentage(7),   // Protocol
            Constraint::Percentage(6),   // Direction
            Constraint::Percentage(7),   // Ports
            Constraint::Percentage(7),   // Action
            Constraint::Percentage(17),  // Stats
            Constraint::Percentage(31),  // Description
        ]
    )
        .header(
            Row::new(vec!["Name", "IP/CIDR", "Protocol", "Dir", "Ports", "Action", "Stats", "Description"])
                .style(Style::default().add_modifier(Modifier::BOLD)),
        )
        .block(Block::default().borders(Borders::ALL).title("Rules"));

    f.render_widget(rules_table, chunks[0]);

    // Logs pane
    let logs = List::new(app.logs.iter().map(|l| ListItem::new(l.as_str())))
        .block(Block::default().borders(Borders::ALL).title("Logs"));
    f.render_widget(logs, chunks[1]);

    // Help bar at the bottom
    let help_text = "Shortcuts: [Q] Quit | Use 'firebee add' command to add rules";
    let help = Paragraph::new(help_text)
        .style(Style::default().fg(Color::Gray))
        .alignment(ratatui::layout::Alignment::Center)
        .block(Block::default().borders(Borders::ALL));
    f.render_widget(help, chunks[2]);

    // Input popup (when input_mode is true)
    if app.input_mode {
        let popup = Paragraph::new(app.input.to_text()).block(
            Block::default()
                .borders(Borders::ALL)
                .title("Enter IP (e.g., 192.168.1.1)"),
        );
        let area = centered_rect(40, 20, f.area());
        f.render_widget(Clear, area);
        f.render_widget(popup, area);
    }

    // Unload confirmation dialog
    if app.confirm_unload {
        let warning_text = vec![
            "WARNING: This will unload the XDP firewall program!",
            "",
            "Are you sure you want to continue?",
            "",
            "Press Y to confirm, N or ESC to cancel",
        ];
        
        let popup = Paragraph::new(warning_text.join("\n"))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("Confirm Unload")
                    .style(Style::default().fg(Color::Red)),
            )
            .alignment(ratatui::layout::Alignment::Center)
            .wrap(Wrap { trim: true });
        
        let area = centered_rect(60, 40, f.area());
        f.render_widget(Clear, area);
        f.render_widget(popup, area);
    }
}

fn format_number(n: u64) -> String {
    if n >= 1_000_000_000 {
        format!("{:.1}B", n as f64 / 1_000_000_000.0)
    } else if n >= 1_000_000 {
        format!("{:.1}M", n as f64 / 1_000_000.0)
    } else if n >= 1_000 {
        format!("{:.1}K", n as f64 / 1_000.0)
    } else {
        format!("{}", n)
    }
}

fn format_bytes(bytes: u64) -> String {
    if bytes >= 1_073_741_824 {
        format!("{:.1}GB", bytes as f64 / 1_073_741_824.0)
    } else if bytes >= 1_048_576 {
        format!("{:.1}MB", bytes as f64 / 1_048_576.0)
    } else if bytes >= 1_024 {
        format!("{:.1}KB", bytes as f64 / 1_024.0)
    } else {
        format!("{}B", bytes)
    }
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}
