use super::outcome::ToolInvocationOutcome;
use crate::{config::Config, daemon_db::DbAccess};

#[derive(Clone, Copy)]
pub struct ToolInvocationContext<'a> {
    pub original_query: &'a str,
    db: Option<&'a dyn DbAccess>,
    session_id: Option<&'a str>,
    pub private: bool,
    pub config: &'a Config,
    pub force_autorun: bool,
    pub render_output: bool,
    pub json_output: bool,
}

impl<'a> ToolInvocationContext<'a> {
    pub fn query(
        original_query: &'a str,
        db: &'a dyn DbAccess,
        session_id: &'a str,
        private: bool,
        config: &'a Config,
        force_autorun: bool,
    ) -> Self {
        Self {
            original_query,
            db: Some(db),
            session_id: Some(session_id),
            private,
            config,
            force_autorun,
            render_output: false,
            json_output: false,
        }
    }

    pub fn standalone(config: &'a Config, force_autorun: bool) -> Self {
        Self {
            original_query: "",
            db: None,
            session_id: None,
            private: false,
            config,
            force_autorun,
            render_output: false,
            json_output: false,
        }
    }

    pub fn with_render_output(mut self, render_output: bool) -> Self {
        self.render_output = render_output;
        self
    }

    pub fn with_json_output(mut self, json_output: bool) -> Self {
        self.json_output = json_output;
        self
    }

    pub fn conversation_state(self) -> anyhow::Result<(&'a dyn DbAccess, &'a str)> {
        match (self.db, self.session_id) {
            (Some(db), Some(session_id)) => Ok((db, session_id)),
            _ => anyhow::bail!("tool invocation context is missing conversation state"),
        }
    }
}

#[derive(Debug, Clone)]
pub enum ToolInvocationResult {
    Continue(ToolInvocationOutcome),
    Terminal,
}

impl ToolInvocationResult {
    pub fn success(content: impl Into<String>) -> Self {
        Self::Continue(ToolInvocationOutcome::success(content))
    }

    #[cfg(test)]
    pub fn failure(content: impl Into<String>) -> Self {
        Self::Continue(ToolInvocationOutcome::failure(content))
    }

    pub fn from_result(result: anyhow::Result<String>) -> Self {
        Self::Continue(ToolInvocationOutcome::from_result(result))
    }

    pub fn terminal() -> Self {
        Self::Terminal
    }

    pub fn into_outcome_or_failure(self, tool_name: &str) -> ToolInvocationOutcome {
        match self {
            Self::Continue(outcome) => outcome,
            Self::Terminal => ToolInvocationOutcome::failure(format!(
                "{tool_name} unexpectedly requested terminal handoff"
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ToolInvocationContext, ToolInvocationResult};
    use crate::config::Config;

    fn test_db() -> crate::db::Db {
        let db = crate::db::Db::open_in_memory().expect("in-memory db");
        db.create_session("s1", "tty0", "zsh", 1234)
            .expect("create session");
        db
    }

    #[test]
    fn query_context_exposes_conversation_state() {
        let db = test_db();
        let config = Config::default();
        let ctx = ToolInvocationContext::query("query", &db, "s1", false, &config, false);
        let (db_ref, session_id) = ctx.conversation_state().expect("conversation state");

        assert_eq!(session_id, "s1");
        assert_eq!(
            db_ref
                .get_conversations("s1", 1)
                .expect("query conversation")
                .len(),
            0
        );
    }

    #[test]
    fn standalone_context_rejects_missing_conversation_state() {
        let config = Config::default();
        let err = match ToolInvocationContext::standalone(&config, false).conversation_state() {
            Ok(_) => panic!("standalone context should not expose db/session"),
            Err(err) => err,
        };

        assert!(err.to_string().contains("missing conversation state"));
    }

    #[test]
    fn terminal_result_degrades_to_failure_for_non_terminal_tools() {
        let outcome = ToolInvocationResult::terminal().into_outcome_or_failure("ask_user");

        assert_eq!(
            outcome.into_parts(),
            (
                "ask_user unexpectedly requested terminal handoff".to_string(),
                true,
            )
        );
    }

    #[test]
    fn with_json_output_overrides_default() {
        let config = Config::default();
        let ctx = ToolInvocationContext::standalone(&config, false).with_json_output(true);

        assert!(ctx.json_output);
    }
}
