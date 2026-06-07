//! Color palette and style helpers.
//!
//! All colors are explicit 24-bit RGB (never ANSI-16) to avoid the rendering
//! glitches that mixing the two causes on some terminals — same convention as
//! codex-switch.
//!
//! This is a complete palette/style library; not every entry is used yet.
#![allow(dead_code)]

use ratatui::style::{Color, Modifier, Style};

pub const BG: Color = Color::Rgb(24, 24, 24);
pub const FG: Color = Color::Rgb(240, 240, 240);
pub const GRAY: Color = Color::Rgb(180, 180, 180);
pub const DIM: Color = Color::Rgb(120, 120, 120);
pub const RED: Color = Color::Rgb(255, 90, 90);
pub const GREEN: Color = Color::Rgb(80, 220, 120);
pub const YELLOW: Color = Color::Rgb(255, 220, 80);
pub const CYAN: Color = Color::Rgb(100, 210, 255);
pub const BLUE: Color = Color::Rgb(80, 140, 220);
pub const HILITE_BG: Color = Color::Rgb(55, 55, 65);

pub fn base() -> Style {
    Style::default().bg(BG).fg(FG)
}

pub fn title() -> Style {
    base().fg(CYAN).add_modifier(Modifier::BOLD)
}

pub fn dim() -> Style {
    base().fg(DIM)
}

pub fn key() -> Style {
    base().fg(YELLOW)
}

pub fn ok() -> Style {
    base().fg(GREEN).add_modifier(Modifier::BOLD)
}

pub fn warn() -> Style {
    base().fg(YELLOW).add_modifier(Modifier::BOLD)
}

pub fn err() -> Style {
    base().fg(RED).add_modifier(Modifier::BOLD)
}

pub fn selected() -> Style {
    base().bg(HILITE_BG).fg(FG).add_modifier(Modifier::BOLD)
}
