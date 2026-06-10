use super::super::AgentState;

pub(super) fn detect(content: &str) -> AgentState {
    // Blocked
    if has_visible_blocker(content) {
        return AgentState::Blocked;
    }

    // Cline defaults to working (unlike most agents that default to idle)
    AgentState::Working
}

pub(super) fn has_visible_blocker(content: &str) -> bool {
    let lower = content.to_lowercase();
    lower.contains("let cline use this tool")
        || ((lower.contains("[act mode]") || lower.contains("[plan mode]"))
            && (lower.contains("execute command?") || lower.contains("use this tool?"))
            && lower.contains("yes"))
}
