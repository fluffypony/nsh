// Centralized theme for terminal styling. Provides 24-bit and 256-color fallbacks.

pub struct Theme {
    pub text: &'static str,
    pub subtext: &'static str,
    pub accent: &'static str,
    pub success: &'static str,
    pub warning: &'static str,
    pub error: &'static str,
    pub spinner: &'static str,
    pub reset: &'static str,
    pub bold: &'static str,
    pub dim: &'static str,
    pub italic: &'static str,
}

// Catppuccin Mocha-inspired
pub const MOCHA: Theme = Theme {
    text: "\x1b[38;2;205;214;244m",
    subtext: "\x1b[38;2;166;173;200m",
    accent: "\x1b[38;2;137;180;250m",
    success: "\x1b[38;2;166;227;161m",
    warning: "\x1b[38;2;249;226;175m",
    error: "\x1b[38;2;243;139;168m",
    spinner: "\x1b[38;2;203;166;247m",
    reset: "\x1b[0m",
    bold: "\x1b[1m",
    dim: "\x1b[2m",
    italic: "\x1b[3m",
};

pub const MOCHA_256: Theme = Theme {
    text: "\x1b[38;5;253m",
    subtext: "\x1b[38;5;250m",
    accent: "\x1b[38;5;111m",
    success: "\x1b[38;5;114m",
    warning: "\x1b[38;5;223m",
    error: "\x1b[38;5;204m",
    spinner: "\x1b[38;5;141m",
    reset: "\x1b[0m",
    bold: "\x1b[1m",
    dim: "\x1b[2m",
    italic: "\x1b[3m",
};

fn supports_truecolor() -> bool {
    std::env::var("COLORTERM")
        .map(|v| v == "truecolor" || v == "24bit")
        .unwrap_or(false)
}

fn supports_256color() -> bool {
    std::env::var("TERM")
        .map(|v| v.contains("256color"))
        .unwrap_or(false)
        || supports_truecolor()
}

pub fn current_theme() -> &'static Theme {
    if supports_truecolor() {
        &MOCHA
    } else if supports_256color() {
        &MOCHA_256
    } else {
        &MOCHA_256
    }
}
