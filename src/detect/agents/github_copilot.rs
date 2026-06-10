use super::super::AgentState;

pub(super) fn detect(content: &str) -> AgentState {
    let lower = content.to_lowercase();

    // Blocked
    if has_visible_blocker(content) {
        return AgentState::Blocked;
    }

    // Working
    if lower.contains("esc to cancel")
        || lower.contains("esc cancel")
        || lower.contains("esc again to cancel")
    {
        return AgentState::Working;
    }

    AgentState::Idle
}

pub(super) fn has_visible_blocker(content: &str) -> bool {
    let lower = content.to_lowercase();
    lower.contains("esc to cancel")
        && (lower.contains("enter to select")
            || lower.contains("enter to confirm")
            || lower.contains("enter to submit"))
}
