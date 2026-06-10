use super::super::{has_braille_spinner, AgentState};

/// Grok Build detection.
///
/// Blocked permission prompts display a whitelist scope selector with choices
/// like "Yes, proceed" and "No, reject". Working turns show a braille spinner
/// status line such as "⠋ Waiting… 1.8s" plus live controls like
/// "Ctrl+c:cancel" and "Ctrl+Enter:interject".
pub(super) fn detect(content: &str) -> AgentState {
    if has_visible_blocker(content) {
        return AgentState::Blocked;
    }

    let lower = content.to_lowercase();
    if has_braille_spinner(content)
        && (lower.contains("waiting")
            || lower.contains("run ")
            || lower.contains("read ")
            || lower.contains("search ")
            || lower.contains("list "))
    {
        return AgentState::Working;
    }

    if lower.contains("ctrl+c:cancel") && lower.contains("ctrl+enter:interject") {
        return AgentState::Working;
    }

    AgentState::Idle
}

pub(super) fn has_visible_blocker(content: &str) -> bool {
    let lower = content.to_lowercase();
    let has_scope_selector = lower.contains("use ← → to choose permission whitelist scope")
        || lower.contains("←/→:scope");
    has_scope_selector && lower.contains("yes, proceed") && lower.contains("no, reject")
}
