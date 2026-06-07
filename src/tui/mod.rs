//! Interactive terminal UI (ratatui + crossterm), modeled on codex-switch:
//! a main list, context-sensitive status bar, footer key hints, and centered
//! popups (form / confirm / help) drawn over the list with a `Clear` layer.

mod app;
mod theme;
mod ui;

use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};

use app::{App, Confirm, FIELDS, FieldKind, Form};

pub fn run(config_path: PathBuf) -> Result<()> {
    // Restore the terminal even if a panic unwinds through the draw loop.
    let hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        ratatui::restore();
        hook(info);
    }));

    let mut terminal = ratatui::init();
    let result = run_loop(&mut terminal, config_path);
    ratatui::restore();
    result
}

fn run_loop(terminal: &mut ratatui::DefaultTerminal, config_path: PathBuf) -> Result<()> {
    let mut app = App::load(config_path);
    while !app.should_quit {
        app.poll_probes();
        terminal.draw(|frame| ui::render(frame, &app))?;
        if event::poll(Duration::from_millis(200))?
            && let Event::Key(key) = event::read()?
            && key.kind == KeyEventKind::Press
        {
            handle_key(&mut app, key.code, key.modifiers);
        }
    }
    Ok(())
}

fn handle_key(app: &mut App, code: KeyCode, mods: KeyModifiers) {
    if app.show_help {
        match code {
            KeyCode::Char('q') | KeyCode::Esc | KeyCode::Char('h') | KeyCode::Char('?') => {
                app.show_help = false;
            }
            KeyCode::Down | KeyCode::Char('j') => {
                app.help_scroll = app.help_scroll.saturating_add(1)
            }
            KeyCode::Up | KeyCode::Char('k') => app.help_scroll = app.help_scroll.saturating_sub(1),
            _ => {}
        }
        return;
    }
    if app.confirm.is_some() {
        let confirmed = matches!(code, KeyCode::Char('y') | KeyCode::Char('Y'));
        let action = app.confirm.take();
        if confirmed {
            match action {
                Some(Confirm::Delete(i)) => {
                    app.selected = i;
                    app.delete_selected();
                }
                Some(Confirm::Apply) => {
                    if app.dirty {
                        app.save();
                    }
                    app.apply();
                }
                None => {}
            }
        } else {
            app.status = "cancelled".into();
        }
        return;
    }
    if app.form.is_some() {
        handle_form_key(app, code);
        return;
    }

    match code {
        KeyCode::Char('q') => app.should_quit = true,
        KeyCode::Char('c') if mods.contains(KeyModifiers::CONTROL) => app.should_quit = true,
        KeyCode::Up | KeyCode::Char('k') => app.move_up(),
        KeyCode::Down | KeyCode::Char('j') => app.move_down(),
        KeyCode::Char('a') => app.open_add_form(),
        KeyCode::Char('e') | KeyCode::Enter => app.open_edit_form(),
        KeyCode::Char(' ') => app.toggle_enabled(),
        KeyCode::Char('m') => app.toggle_masquerade(),
        KeyCode::Char('d') if !app.cfg.mappings.is_empty() => {
            app.confirm = Some(Confirm::Delete(app.selected));
            app.status = "delete selected rule? y to confirm".into();
        }
        KeyCode::Char('w') => app.save(),
        KeyCode::Char('A') => {
            app.confirm = Some(Confirm::Apply);
            app.status = "save and apply rules? y to confirm".into();
        }
        KeyCode::Char('r') => app.reload(),
        KeyCode::Char('p') => app.probe_selected(),
        KeyCode::Char('P') => app.probe_all(),
        KeyCode::Char('h') | KeyCode::Char('?') => {
            app.show_help = true;
            app.help_scroll = 0;
        }
        _ => {}
    }
}

fn handle_form_key(app: &mut App, code: KeyCode) {
    match code {
        KeyCode::Esc => {
            app.form = None;
            app.status = "edit cancelled".into();
        }
        KeyCode::Enter => app.commit_form(),
        KeyCode::Tab | KeyCode::Down => {
            if let Some(f) = app.form.as_mut() {
                f.field = (f.field + 1) % FIELDS.len();
            }
        }
        KeyCode::BackTab | KeyCode::Up => {
            if let Some(f) = app.form.as_mut() {
                f.field = (f.field + FIELDS.len() - 1) % FIELDS.len();
            }
        }
        KeyCode::Left | KeyCode::Right => {
            if let Some(f) = app.form.as_mut() {
                toggle_value(f);
            }
        }
        KeyCode::Backspace => {
            if let Some(f) = app.form.as_mut()
                && matches!(FIELDS[f.field].kind, FieldKind::Text)
            {
                f.values[f.field].pop();
            }
        }
        KeyCode::Char(c) => {
            if let Some(f) = app.form.as_mut() {
                match FIELDS[f.field].kind {
                    FieldKind::Text => f.values[f.field].push(c),
                    _ if c == ' ' => toggle_value(f),
                    _ => {}
                }
            }
        }
        _ => {}
    }
}

fn toggle_value(f: &mut Form) {
    let v = &mut f.values[f.field];
    match FIELDS[f.field].kind {
        FieldKind::Proto => {
            *v = if v == "tcp" {
                "udp".into()
            } else {
                "tcp".into()
            }
        }
        FieldKind::Bool => {
            *v = if v == "true" {
                "false".into()
            } else {
                "true".into()
            }
        }
        FieldKind::Text => {}
    }
}
