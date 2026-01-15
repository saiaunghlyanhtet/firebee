use crate::ui::app::App;
use ratatui::{prelude::*, text::ToText, widgets::*};

pub fn render_ui(f: &mut Frame, app: &mut App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(
            [
                Constraint::Percentage(50),
                Constraint::Percentage(45),
                Constraint::Length(3),
            ]
            .as_ref(),
        )
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
        let (packets, bytes) = app
            .rule_stats
            .get(&r.name)
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
            Constraint::Percentage(11), // Name
            Constraint::Percentage(14), // IP/CIDR
            Constraint::Percentage(7),  // Protocol
            Constraint::Percentage(6),  // Direction
            Constraint::Percentage(7),  // Ports
            Constraint::Percentage(7),  // Action
            Constraint::Percentage(17), // Stats
            Constraint::Percentage(31), // Description
        ],
    )
    .header(
        Row::new(vec![
            "Name",
            "IP/CIDR",
            "Protocol",
            "Dir",
            "Ports",
            "Action",
            "Stats",
            "Description",
        ])
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
        let warning_text = [
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_number_single_digits() {
        assert_eq!(format_number(0), "0");
        assert_eq!(format_number(9), "9");
        assert_eq!(format_number(99), "99");
        assert_eq!(format_number(999), "999");
    }

    #[test]
    fn test_format_number_thousands() {
        assert_eq!(format_number(1_000), "1.0K");
        assert_eq!(format_number(1_500), "1.5K");
        assert_eq!(format_number(999_999), "1000.0K");
    }

    #[test]
    fn test_format_number_millions() {
        assert_eq!(format_number(1_000_000), "1.0M");
        assert_eq!(format_number(5_500_000), "5.5M");
        assert_eq!(format_number(999_999_999), "1000.0M");
    }

    #[test]
    fn test_format_number_billions() {
        assert_eq!(format_number(1_000_000_000), "1.0B");
        assert_eq!(format_number(5_500_000_000), "5.5B");
        assert_eq!(format_number(u64::MAX), "18446744073.7B");
    }

    #[test]
    fn test_format_bytes_small() {
        assert_eq!(format_bytes(0), "0B");
        assert_eq!(format_bytes(1), "1B");
        assert_eq!(format_bytes(512), "512B");
        assert_eq!(format_bytes(1023), "1023B");
    }

    #[test]
    fn test_format_bytes_kilobytes() {
        assert_eq!(format_bytes(1_024), "1.0KB");
        assert_eq!(format_bytes(1_536), "1.5KB");
        assert_eq!(format_bytes(1_048_575), "1024.0KB");
    }

    #[test]
    fn test_format_bytes_megabytes() {
        assert_eq!(format_bytes(1_048_576), "1.0MB");
        assert_eq!(format_bytes(5_242_880), "5.0MB");
        assert_eq!(format_bytes(1_073_741_823), "1024.0MB");
    }

    #[test]
    fn test_format_bytes_gigabytes() {
        assert_eq!(format_bytes(1_073_741_824), "1.0GB");
        assert_eq!(format_bytes(5_368_709_120), "5.0GB");
        // u64::MAX formatting - check that it produces reasonable output
        let max_formatted = format_bytes(u64::MAX);
        assert!(max_formatted.ends_with("GB"));
        assert!(max_formatted.starts_with("17179869"));
    }

    #[test]
    fn test_format_bytes_precision() {
        assert_eq!(format_bytes(1_536), "1.5KB");
        assert_eq!(format_bytes(2_621_440), "2.5MB");
        assert_eq!(format_bytes(2_684_354_560), "2.5GB");
    }
}
