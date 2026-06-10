use super::super::AgentState;

/// Qodercli detection.
///
/// Qodercli is a Node.js coding-agent CLI. It surfaces a confirmation prompt
/// while awaiting tool approval and a braille spinner while working.
pub(super) fn detect(content: &str) -> AgentState {
    let lower = content.to_lowercase();

    if has_visible_blocker(content) {
        return AgentState::Blocked;
    }

    // Working: explicit "(esc to cancel, …)" hint or an active spinner row.
    if has_qodercli_working_hint(&lower) || has_qodercli_spinner_row(content) {
        return AgentState::Working;
    }

    AgentState::Idle
}

/// Working hints qodercli prints alongside the spinner while the model is
/// responding. The "(esc to cancel, …)" suffix is unique to qodercli's loading
/// indicator and survives even when the spinner glyph is masked (e.g. by
/// a hook icon).
fn has_qodercli_working_hint(lower_content: &str) -> bool {
    lower_content.contains("(esc to cancel,")
}

/// Strict spinner-row detection for qodercli.
///
/// Matches a line whose first non-whitespace glyph is a braille pattern
/// (U+2800–U+28FF, the cli-spinners "dots" set qodercli renders), followed by
/// a space and at least one alphabetic character on the same line. This avoids
/// flagging the pane as Working when the scrollback merely contains a stale
/// braille glyph from an earlier frame.
fn has_qodercli_spinner_row(content: &str) -> bool {
    for line in content.lines() {
        let trimmed = line.trim_start();
        let mut chars = trimmed.chars();
        let Some(first) = chars.next() else {
            continue;
        };
        if !('\u{2800}'..='\u{28FF}').contains(&first) {
            continue;
        }
        let rest: String = chars.collect();
        if rest.starts_with(' ') && rest.chars().any(|c| c.is_alphabetic()) {
            return true;
        }
    }
    false
}

/// Blocked patterns specific to qodercli.
///
/// Mirrors the helper structure used by Claude blocked prompt matching so the
/// pattern surface stays a single, easy-to-extend list.
///
/// Covered states:
/// * Tool-call confirmation banners ("Waiting for user confirmation",
///   "Awaiting approval").
/// * The "Permission Required / Allow once or always?" approval dialog.
/// * The `ask-user` tool's interactive prompt. "Asking User" is the dialog's
///   stable BaseTabDialog title and covers every form (single-select,
///   multi-select, free-form input, review tab). The "Enter your response"
///   placeholder and "Review your answers:" review heading are kept as
///   defensive fallbacks in case the title row scrolls off-screen.
/// * The interactive shell waiting hint emitted by qodercli when an agent
///   spawns a shell that is now parked for user keystrokes.
pub(super) fn has_visible_blocker(content: &str) -> bool {
    let lower_content = content.to_lowercase();
    (lower_content.contains("waiting for user confirmation")
        && (lower_content.contains("yes")
            || lower_content.contains("no")
            || lower_content.contains("allow")
            || lower_content.contains("reject")))
        || (lower_content.contains("awaiting approval")
            && (lower_content.contains("allow") || lower_content.contains("reject")))
        || lower_content.contains("permission required")
        || lower_content.contains("allow once or always?")
        || lower_content.contains("asking user")
        || lower_content.contains("enter your response")
        || lower_content.contains("review your answers:")
        || lower_content.contains("shell awaiting input")
}
