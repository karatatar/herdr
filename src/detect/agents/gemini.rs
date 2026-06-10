use super::super::AgentState;

pub(super) fn detect(content: &str) -> AgentState {
    if has_visible_blocker(content) {
        return AgentState::Blocked;
    }

    let lower = content.to_lowercase();
    // Working
    if lower.contains("esc to cancel") {
        return AgentState::Working;
    }

    AgentState::Idle
}

pub(super) fn has_visible_blocker(content: &str) -> bool {
    let lower = content.to_lowercase();
    let has_choice = lower.contains("yes") || lower.contains("no");

    content.contains("│ Apply this change")
        || content.contains("│ Allow execution")
        || (has_choice
            && (lower.contains("waiting for user confirmation")
                || content.contains("│ Do you want to proceed")
                || lower.contains("do you want to proceed?")))
        || content.lines().any(|line| {
            let line = line.trim().to_ascii_lowercase();
            line.starts_with("❯") && (line.contains("yes") || line.contains("allow"))
        })
}
