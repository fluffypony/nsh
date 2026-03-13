#[derive(Clone)]
pub struct ToolHandlerContext {
    pub config: crate::config::Config,
}

impl ToolHandlerContext {
    pub fn new(config: &crate::config::Config) -> Self {
        Self {
            config: config.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ToolHandlerContext;

    #[test]
    fn new_clones_config_state() {
        let mut config = crate::config::Config::default();
        config.provider.default = "openai".into();
        config.context.scrollback_lines = 2048;

        let ctx = ToolHandlerContext::new(&config);

        assert_eq!(ctx.config.provider.default, "openai");
        assert_eq!(ctx.config.context.scrollback_lines, 2048);
    }
}
