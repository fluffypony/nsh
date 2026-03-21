pub mod ask_user;
pub mod chat;
pub mod command;
pub mod github;
pub mod glob;
pub mod grep_file;
pub mod install_mcp;
pub mod install_skill;
pub mod list_directory;
pub mod man_page;
pub mod manage_config;
pub mod memory;
pub mod patch_file;
pub mod read_file;
pub mod run_command;
pub mod search_history;
pub mod skill_exists;
pub mod uninstall_skill;
pub mod web_search;
pub mod write_file;

pub(crate) mod runtime;

pub(crate) use runtime::file_tools::{
    default_read_path, ensure_directory, open_for_read, open_regular_read_file, read_failure,
    required_read_path,
};
#[cfg(test)]
pub(crate) use runtime::file_tools::{execute_file_tool_content, execute_file_tool_result};
pub use runtime::invocation::{ToolInvocationContext, ToolInvocationResult};
pub use runtime::outcome::ToolInvocationOutcome;
pub(crate) use runtime::process_pump;
pub use runtime::registry::{ToolDefinition, all_tool_definitions};
pub(crate) use runtime::side_effects::{ToolConversationRecord, record_tool_conversation};
pub use runtime::timeout_policy::default_timeout_for_tool;
pub(crate) use runtime::tty_prompts::read_terminal_line_with;
pub use runtime::tty_prompts::{
    prompt_tty_confirmation, read_tty_confirmation, read_tty_confirmation_default_yes,
    read_tty_confirmation_safe, read_tty_yes_confirmation, read_user_input_with_timeout,
};

#[cfg(test)]
mod tests;
