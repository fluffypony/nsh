pub mod engine;
pub mod prompt_builder;
pub mod ranker;
pub mod topic_extractor;

use crate::memory::types::InteractionMode;

pub fn needs_full_retrieval(mode: InteractionMode) -> bool {
    matches!(
        mode,
        InteractionMode::NaturalLanguage
            | InteractionMode::ErrorFix
            | InteractionMode::CodeGeneration
            | InteractionMode::AutonomousExecution
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn needs_full_retrieval_natural_language() {
        assert!(needs_full_retrieval(
            crate::memory::types::InteractionMode::NaturalLanguage
        ));
    }

    #[test]
    fn needs_full_retrieval_error_fix() {
        assert!(needs_full_retrieval(
            crate::memory::types::InteractionMode::ErrorFix
        ));
    }

    #[test]
    fn needs_full_retrieval_code_generation() {
        assert!(needs_full_retrieval(
            crate::memory::types::InteractionMode::CodeGeneration
        ));
    }

    #[test]
    fn needs_full_retrieval_autonomous() {
        assert!(needs_full_retrieval(
            crate::memory::types::InteractionMode::AutonomousExecution
        ));
    }

    #[test]
    fn does_not_need_full_retrieval_command_suggestion() {
        assert!(!needs_full_retrieval(
            crate::memory::types::InteractionMode::CommandSuggestion
        ));
    }
}
