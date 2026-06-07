//! Rendering for the TUI.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Clear, Paragraph, Row, Table, TableState, Wrap};

use super::app::{App, Confirm, FIELDS, FieldKind};
use super::theme;

pub fn render(f: &mut Frame, app: &App) {
    let area = f.area();
    f.render_widget(Block::default().style(theme::base()), area);

    let chunks = Layout::vertical([
        Constraint::Min(6),
        Constraint::Length(7),
        Constraint::Length(2),
    ])
    .split(area);

    render_list(f, app, chunks[0]);
    render_detail(f, app, chunks[1]);
    render_status(f, app, chunks[2]);

    if app.form.is_some() {
        render_form(f, app, area);
    }
    if app.show_help {
        render_help(f, app, area);
    }
}

fn render_list(f: &mut Frame, app: &App, area: Rect) {
    let dirty = if app.dirty { "  *modified" } else { "" };
    let title = format!(" Mappings ({}){} ", app.cfg.mappings.len(), dirty);
    let block = Block::default()
        .title(Span::styled(title, theme::title()))
        .borders(Borders::ALL)
        .border_style(theme::base().fg(theme::BLUE))
        .style(theme::base());

    if app.cfg.mappings.is_empty() {
        let p = Paragraph::new("No rules. Press 'a' to add a port-forwarding rule.")
            .style(theme::dim())
            .block(block);
        f.render_widget(p, area);
        return;
    }

    let header = Row::new([
        "", "ID", "Proto", "Listen", "Target", "On", "Masq", "Latency",
    ])
    .style(theme::base().fg(theme::CYAN))
    .height(1);

    let rows = app.cfg.mappings.iter().enumerate().map(|(i, m)| {
        let marker = if i == app.selected { ">" } else { " " };
        let on = if m.enabled { "yes" } else { "no" };
        let masq = if m.masquerade { "yes" } else { "no" };
        let row_style = if m.enabled {
            theme::base()
        } else {
            theme::dim()
        };
        let (lat, lat_style) = latency_cell(app, &m.id);
        Row::new(vec![
            Cell::from(marker),
            Cell::from(truncate(&m.id, 18)),
            Cell::from(m.protocol.to_string().to_uppercase()),
            Cell::from(format!("{}:{}", m.listen_ip, m.listen_port)),
            Cell::from(format!("{}:{}", m.target_ip, m.target_port)),
            Cell::from(on),
            Cell::from(masq),
            Cell::from(lat).style(lat_style),
        ])
        .style(row_style)
    });

    let widths = [
        Constraint::Length(1),
        Constraint::Length(18),
        Constraint::Length(5),
        Constraint::Length(21),
        Constraint::Length(23),
        Constraint::Length(3),
        Constraint::Length(4),
        Constraint::Min(8),
    ];
    let table = Table::new(rows, widths)
        .header(header)
        .row_highlight_style(theme::selected())
        .block(block)
        .style(theme::base());

    let mut state = TableState::default();
    state.select(Some(app.selected));
    f.render_stateful_widget(table, area, &mut state);
}

fn latency_cell(app: &App, id: &str) -> (String, ratatui::style::Style) {
    if app.probing.contains(id) {
        return ("…".to_string(), theme::dim());
    }
    match app.probes.get(id) {
        Some(r) if r.latency.is_some() => (r.display(), theme::base().fg(theme::GREEN)),
        Some(_) => ("✗".to_string(), theme::base().fg(theme::RED)),
        None => ("-".to_string(), theme::dim()),
    }
}

fn render_detail(f: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .title(Span::styled(" Selected Rule ", theme::title()))
        .borders(Borders::ALL)
        .border_style(theme::base().fg(theme::BLUE))
        .style(theme::base());

    let lines: Vec<Line> = match app.selected_mapping() {
        None => vec![Line::styled("No rule selected.", theme::dim())],
        Some(m) => {
            vec![
                Line::from(vec![
                    Span::styled("name ", theme::dim()),
                    Span::raw(value_or(&m.name, "-")),
                ]),
                Line::from(format!(
                    "{}:{}/{}  →  {}:{}",
                    m.listen_ip, m.listen_port, m.protocol, m.target_ip, m.target_port
                )),
                Line::from(format!(
                    "enabled={}  masquerade={}",
                    m.enabled, m.masquerade
                )),
                {
                    let (txt, style) = latency_cell(app, &m.id);
                    let method = app.probes.get(&m.id).map(|r| r.method).unwrap_or("");
                    let suffix = if method.is_empty() {
                        String::new()
                    } else {
                        format!("  ({method})")
                    };
                    Line::from(vec![
                        Span::styled("target latency ", theme::dim()),
                        Span::styled(txt, style),
                        Span::styled(suffix, theme::dim()),
                        Span::styled("   (p to probe)", theme::dim()),
                    ])
                },
            ]
        }
    };
    f.render_widget(
        Paragraph::new(lines).block(block).style(theme::base()),
        area,
    );
}

fn render_status(f: &mut Frame, app: &App, area: Rect) {
    let msg = match &app.confirm {
        Some(Confirm::Delete(_)) => Line::styled(
            "Delete selected rule? y confirms, any other key cancels",
            theme::err(),
        ),
        Some(Confirm::Apply) => Line::styled(
            "Save and apply rules? y confirms, any other key cancels",
            theme::warn(),
        ),
        None => Line::styled(app.status.clone(), theme::warn()),
    };

    let hints = Line::from(key_hints());
    f.render_widget(Paragraph::new(vec![msg, hints]).style(theme::base()), area);
}

fn key_hints() -> Vec<Span<'static>> {
    let mut spans = Vec::new();
    let items = [
        ("a", "add"),
        ("e", "edit"),
        ("space", "on/off"),
        ("m", "masq"),
        ("d", "del"),
        ("w", "save"),
        ("A", "apply"),
        ("p", "probe"),
        ("r", "reload"),
        ("h", "help"),
        ("q", "quit"),
    ];
    for (i, (k, label)) in items.iter().enumerate() {
        if i > 0 {
            spans.push(Span::styled(" · ", theme::dim()));
        }
        spans.push(Span::styled(*k, theme::key()));
        spans.push(Span::styled(
            format!(" {label}"),
            theme::base().fg(theme::GRAY),
        ));
    }
    spans
}

fn render_form(f: &mut Frame, app: &App, area: Rect) {
    let Some(form) = &app.form else { return };
    let title = if form.edit_index.is_some() {
        " Edit Rule "
    } else {
        " Add Rule "
    };
    let h = (FIELDS.len() as u16) + 4;
    let rect = centered(area, 64, h);
    f.render_widget(Clear, rect);

    let mut lines: Vec<Line> = Vec::new();
    for (i, spec) in FIELDS.iter().enumerate() {
        let active = i == form.field;
        let marker = if active { ">" } else { " " };
        let mut value = if form.values[i].is_empty() {
            "<empty>".to_string()
        } else {
            form.values[i].clone()
        };
        if active && matches!(spec.kind, FieldKind::Text) {
            value.push('█');
        }
        let hint = match spec.kind {
            FieldKind::Text if active => "  type/backspace",
            FieldKind::Text => "",
            _ if active => "  ←/→/space toggles",
            _ => "",
        };
        let label_style = if active { theme::key() } else { theme::dim() };
        let value_style = if active {
            theme::selected()
        } else if form.values[i].is_empty() {
            theme::dim()
        } else {
            theme::base()
        };
        lines.push(Line::from(vec![
            Span::styled(marker, label_style),
            Span::raw(" "),
            Span::styled(format!("{:<12}", spec.label), label_style),
            Span::styled(" ", theme::base()),
            Span::styled(value, value_style),
            Span::styled(hint, theme::dim()),
        ]));
    }
    lines.push(Line::from(""));
    lines.push(Line::styled(
        "Tab/↑↓ move · ←/→ toggle · Enter save · Esc cancel",
        theme::dim(),
    ));

    let block = Block::default()
        .title(Span::styled(title, theme::title()))
        .borders(Borders::ALL)
        .border_style(theme::base().fg(theme::CYAN))
        .style(theme::base());
    f.render_widget(
        Paragraph::new(lines).block(block).style(theme::base()),
        rect,
    );
}

fn render_help(f: &mut Frame, app: &App, area: Rect) {
    let rect = centered(area, 56, 20);
    f.render_widget(Clear, rect);
    let lines = vec![
        Line::styled("NPorter — Rule Manager", theme::title()),
        Line::from(""),
        Line::from("Manages port-forwarding rules in the config file."),
        Line::from("Changes are in-memory until you save (w)."),
        Line::from(""),
        Line::styled("List", theme::key()),
        Line::from("  a        add a rule"),
        Line::from("  e/enter  edit selected rule"),
        Line::from("  space    enable / disable selected rule"),
        Line::from("  m        toggle masquerade"),
        Line::from("  d        delete selected rule"),
        Line::from("  w        save config"),
        Line::from("  A        save and apply to the kernel"),
        Line::from("  p / P    probe target latency (selected / all)"),
        Line::from("  r        reload from disk"),
        Line::from("  j/k ↑↓   move selection"),
        Line::from(""),
        Line::styled("Form", theme::key()),
        Line::from("  Tab/↑↓   next/prev field"),
        Line::from("  ←/→/spc  toggle protocol / bool"),
        Line::from("  Enter    save rule    Esc cancel"),
        Line::from(""),
        Line::styled("q / h / esc closes this help.", theme::dim()),
    ];
    let block = Block::default()
        .title(Span::styled(" Help ", theme::title()))
        .borders(Borders::ALL)
        .border_style(theme::base().fg(theme::CYAN))
        .style(theme::base());
    f.render_widget(
        Paragraph::new(lines)
            .block(block)
            .style(theme::base())
            .scroll((app.help_scroll, 0))
            .wrap(Wrap { trim: false }),
        rect,
    );
}

fn centered(area: Rect, w: u16, h: u16) -> Rect {
    let w = w.min(area.width);
    let h = h.min(area.height);
    Rect {
        x: area.x + (area.width.saturating_sub(w)) / 2,
        y: area.y + (area.height.saturating_sub(h)) / 2,
        width: w,
        height: h,
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        return s.to_string();
    }
    let mut out: String = s.chars().take(n.saturating_sub(1)).collect();
    out.push('…');
    out
}

fn value_or(s: &str, fallback: &str) -> String {
    if s.is_empty() {
        fallback.to_string()
    } else {
        s.to_string()
    }
}
