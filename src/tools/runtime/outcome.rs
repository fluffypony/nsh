#[derive(Debug, Clone)]
pub enum ToolInvocationOutcome {
    Success(String),
    Failure(String),
}

impl ToolInvocationOutcome {
    pub fn success(content: impl Into<String>) -> Self {
        Self::Success(content.into())
    }

    pub fn failure(content: impl Into<String>) -> Self {
        Self::Failure(content.into())
    }

    pub fn from_result(result: anyhow::Result<String>) -> Self {
        match result {
            Ok(content) => Self::Success(content),
            Err(err) => Self::Failure(err.to_string()),
        }
    }

    pub fn into_parts(self) -> (String, bool) {
        match self {
            Self::Success(content) => (content, false),
            Self::Failure(content) => (content, true),
        }
    }

    pub fn into_content(self) -> String {
        match self {
            Self::Success(content) | Self::Failure(content) => content,
        }
    }
}

#[cfg(test)]
pub fn outcome_to_content(result: anyhow::Result<ToolInvocationOutcome>) -> anyhow::Result<String> {
    result.map(ToolInvocationOutcome::into_content)
}

#[cfg(test)]
pub fn outcome_to_result(result: anyhow::Result<ToolInvocationOutcome>) -> anyhow::Result<String> {
    match result? {
        ToolInvocationOutcome::Success(content) => Ok(content),
        ToolInvocationOutcome::Failure(content) => Err(anyhow::anyhow!(content)),
    }
}

#[cfg(test)]
mod tests {
    use super::{ToolInvocationOutcome, outcome_to_content, outcome_to_result};

    #[test]
    fn from_result_and_into_parts_preserve_success_state() {
        let outcome = ToolInvocationOutcome::from_result(Ok("done".to_string()));

        assert_eq!(outcome.into_parts(), ("done".to_string(), false));
    }

    #[test]
    fn failure_helpers_preserve_error_state() {
        let created = ToolInvocationOutcome::failure("boom");
        let from_result = ToolInvocationOutcome::from_result(Err(anyhow::anyhow!("bad input")));

        assert_eq!(created.into_parts(), ("boom".to_string(), true));
        assert_eq!(from_result.into_content(), "bad input");
    }

    #[test]
    fn outcome_to_content_flattens_both_states() {
        let success = outcome_to_content(Ok(ToolInvocationOutcome::success("ok"))).unwrap();
        let failure = outcome_to_content(Ok(ToolInvocationOutcome::failure("nope"))).unwrap();

        assert_eq!(success, "ok");
        assert_eq!(failure, "nope");
    }

    #[test]
    fn outcome_to_result_turns_failures_into_errors() {
        let err = outcome_to_result(Ok(ToolInvocationOutcome::failure("blocked"))).unwrap_err();

        assert!(err.to_string().contains("blocked"));
    }
}
