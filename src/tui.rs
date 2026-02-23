//! Shared TUI rendering primitives — Charmbracelet-inspired styling.
//! Centralizes terminal width detection, box drawing, word wrapping,
//! ANSI color constants, and reusable display helpers.

// Note: Avoid importing std::io::Write here to prevent unused import warnings.

// ─── ANSI Style Constants ────────────────────────────────────────────
pub mod theme;

pub mod style {
    pub const RESET: &str = "\x1b[0m";
    pub const BOLD: &str = "\x1b[1m";
    pub const DIM: &str = "\x1b[2m";
    pub const ITALIC: &str = "\x1b[3m";
    pub const UNDERLINE: &str = "\x1b[4m";

    pub const RED: &str = "\x1b[31m";
    pub const GREEN: &str = "\x1b[32m";
    pub const YELLOW: &str = "\x1b[33m";
    pub const BLUE: &str = "\x1b[34m";
    pub const MAGENTA: &str = "\x1b[35m";
    pub const CYAN: &str = "\x1b[36m";
    pub const WHITE: &str = "\x1b[37m";

    pub const BOLD_RED: &str = "\x1b[1;31m";
    pub const BOLD_GREEN: &str = "\x1b[1;32m";
    pub const BOLD_YELLOW: &str = "\x1b[1;33m";
    pub const BOLD_CYAN: &str = "\x1b[1;36m";
    pub const BOLD_MAGENTA: &str = "\x1b[1;35m";

    // 256-colour palette for richer theming
    pub const BRIGHT_RED: &str = "\x1b[1;38;5;196m";
    pub const ORANGE: &str = "\x1b[1;38;5;214m";
    pub const PURPLE: &str = "\x1b[38;5;99m";
    pub const BRIGHT_CYAN: &str = "\x1b[38;5;14m";
    pub const SOFT_BLUE: &str = "\x1b[1;38;5;39m";
    pub const PINK: &str = "\x1b[1;38;5;212m";
    pub const LIGHT_GRAY: &str = "\x1b[38;5;244m";
    pub const OFF_WHITE: &str = "\x1b[38;5;253m";

    pub const CYAN_ITALIC: &str = "\x1b[3;36m";
    pub const DIM_CYAN: &str = "\x1b[2;36m";
}

// ─── Terminal Helpers ────────────────────────────────────────────────

/// Return the current terminal width, defaulting to 80 if detection fails.
pub fn term_width() -> usize {
    crossterm::terminal::size()
        .map(|(w, _)| w as usize)
        .unwrap_or(80)
}

// ─── Text Wrapping ──────────────────────────────────────────────────

/// Word-wrap `text` to fit within `width` display columns.
/// Preserves explicit newlines. Handles words wider than `width` by
/// placing them on their own line (no mid-word break).
pub fn wrap_text(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    for paragraph in text.lines() {
        if paragraph.trim().is_empty() {
            lines.push(String::new());
            continue;
        }
        let mut current_line = String::new();
        for word in paragraph.split_whitespace() {
            let word_len = word.chars().count();
            let cur_len = current_line.chars().count();
            if current_line.is_empty() {
                current_line.push_str(word);
            } else if cur_len + 1 + word_len <= width {
                current_line.push(' ');
                current_line.push_str(word);
            } else {
                lines.push(current_line);
                current_line = word.to_string();
            }
        }
        if !current_line.is_empty() {
            lines.push(current_line);
        }
    }
    if lines.is_empty() {
        lines.push(String::new());
    }
    lines
}

/// Pad string `s` with trailing spaces so its display width equals `width`.
pub fn pad_right(s: &str, width: usize) -> String {
    let char_count = s.chars().count();
    if char_count >= width {
        s.to_string()
    } else {
        format!("{}{}", s, " ".repeat(width - char_count))
    }
}

// ─── Box Drawing (Charmbracelet-style rounded corners) ──────────────

pub enum BoxStyle {
    Safe,
    Elevated,
    Dangerous,
    Info,
    Question,
}

impl BoxStyle {
    fn colors(&self) -> (&'static str, &'static str) {
        use style::*;
        match self {
            BoxStyle::Safe => (LIGHT_GRAY, BOLD_CYAN),
            BoxStyle::Elevated => (ORANGE, ORANGE),
            BoxStyle::Dangerous => (BRIGHT_RED, BRIGHT_RED),
            BoxStyle::Info => (SOFT_BLUE, SOFT_BLUE),
            BoxStyle::Question => (PINK, PINK),
        }
    }
}

/// Render a Charmbracelet-inspired rounded-corner box that stretches
/// to the full terminal width. `label` appears in the top border.
/// Each `ContentLine` can be dimmed (explanation) or bold (command).
pub struct ContentLine {
    pub text: String,
    pub dim: bool,
}

pub fn render_box(label: &str, content: &[ContentLine], box_style: BoxStyle) {
    let tw = term_width();
    let box_width = tw.saturating_sub(2).max(40);
    let inner_width = box_width.saturating_sub(4); // border + 1 space each side

    let th = crate::tui::theme::current_theme();
    let (border_color, title_color) = box_style.colors();
    let reset = th.reset;
    let dim = th.dim;
    let bold = th.bold;

    // Top border: ╭─ label ──────────╮
    let label_display = if label.is_empty() { String::new() } else { format!(" {label} ") };
    let label_len = label_display.chars().count();
    let top_dashes = box_width.saturating_sub(3 + label_len); // 3 = ╭─ + ╮
    eprintln!(
        "  {border_color}╭─{title_color}{label_display}{border_color}{:─<top_dashes$}╮{reset}",
        ""
    );

    // Content lines
    for cl in content {
        let wrapped = wrap_text(&cl.text, inner_width);
        for line in &wrapped {
            let padded = pad_right(line, inner_width);
            if cl.dim {
                eprintln!("  {border_color}│{reset} {dim}{padded}{reset} {border_color}│{reset}");
            } else {
                eprintln!("  {border_color}│{reset} {bold}{padded}{reset} {border_color}│{reset}");
            }
        }
    }

    // Bottom border: ╰──────────────────╯
    let bottom_dashes = box_width.saturating_sub(2);
    eprintln!(
        "  {border_color}╰{:─<bottom_dashes$}╯{reset}",
        ""
    );
}

/// Convenience: render a simple info/status box with a single text block.
pub fn render_simple_box(label: &str, text: &str, box_style: BoxStyle) {
    render_box(
        label,
        &[ContentLine { text: text.to_string(), dim: false }],
        box_style,
    );
}

// ─── Section Headers ────────────────────────────────────────────────

/// Print a full-width section header: ── Title ────────────────
pub fn section_header(title: &str) {
    let w = term_width().saturating_sub(2);
    let label = format!(" {title} ");
    let label_len = label.chars().count();
    let padding = w.saturating_sub(label_len + 3);
    let th = crate::tui::theme::current_theme();
    eprintln!("  {}── {} {}{}", th.accent, title, "─".repeat(padding), th.reset);
}

/// Print a subtle horizontal rule.
pub fn hr() {
    let w = term_width().saturating_sub(4);
    let th = crate::tui::theme::current_theme();
    eprintln!("  {}{}{}", th.dim, "─".repeat(w), th.reset);
}

// ─── Status Line Helpers ────────────────────────────────────────────

/// Tool action indicator: ◆ doing something…
pub fn tool_status(message: &str) {
    let th = crate::tui::theme::current_theme();
    eprintln!("  {}◆{} {}{}{}", th.accent, th.reset, th.dim, message, th.reset);
}

/// Error indicator: ✖ something failed
pub fn tool_error(message: &str) {
    let th = crate::tui::theme::current_theme();
    eprintln!("  {}✖{} {}{}{}", th.error, th.reset, th.error, message, th.reset);
}

/// Success indicator: ✓ something worked
pub fn tool_success(message: &str) {
    let th = crate::tui::theme::current_theme();
    eprintln!("  {}✓{} {}{}{}", th.success, th.reset, th.dim, message, th.reset);
}

// ─── Tool Start/Finish Dividers ─────────────────────────────────────

/// Subtle divider showing tool execution start.
pub fn tool_divider(tool_name: &str) {
    let w = term_width().saturating_sub(4);
    let label = format!(" {tool_name} ");
    let label_len = label.chars().count();
    let pad = w.saturating_sub(label_len);
    let th = crate::tui::theme::current_theme();
    eprintln!("  {}{}{}{}", th.dim, label, "─".repeat(pad), th.reset);
}
