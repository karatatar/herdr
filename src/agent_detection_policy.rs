use crate::detect::{Agent, AgentDetection, AgentState};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PtySignal {
    pub active: bool,
    pub tainted: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DetectionPolicyInput {
    pub agent: Option<Agent>,
    pub screen_detection: AgentDetection,
    pub process_exited: bool,
    pub startup_grace_active: bool,
    pub pty_signal: Option<PtySignal>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DetectionPolicyDecision {
    Publish(AgentDetection),
    Freeze,
}

fn screen_blocked_or_idle_fallback(detection: AgentDetection) -> AgentDetection {
    if detection.visible_blocker {
        return AgentDetection {
            state: AgentState::Blocked,
            skip_state_update: false,
            visible_blocker: true,
            visible_working: false,
        };
    }

    AgentDetection {
        state: AgentState::Idle,
        skip_state_update: false,
        visible_blocker: false,
        visible_working: false,
    }
}

#[cfg(test)]
pub(crate) fn full_lifecycle_detected_agent(agent: Agent) -> bool {
    matches!(
        agent,
        Agent::Pi | Agent::Hermes | Agent::OpenCode | Agent::Kilo
    )
}

pub(crate) fn full_lifecycle_hook_authority(source: &str, agent_label: &str) -> bool {
    matches!(
        (source, agent_label),
        ("herdr:pi", "pi")
            | ("herdr:omp", "omp")
            | ("herdr:hermes", "hermes")
            | ("herdr:opencode", "opencode")
            | ("herdr:kilo", "kilo")
    )
}

pub(crate) fn apply_detection_policy(input: DetectionPolicyInput) -> DetectionPolicyDecision {
    if input.process_exited {
        return DetectionPolicyDecision::Publish(input.screen_detection);
    }

    if input.startup_grace_active {
        return DetectionPolicyDecision::Freeze;
    }

    if input.agent.is_none() {
        return DetectionPolicyDecision::Publish(input.screen_detection);
    };

    let Some(pty_signal) = input.pty_signal else {
        return DetectionPolicyDecision::Publish(input.screen_detection);
    };

    if pty_signal.tainted {
        return DetectionPolicyDecision::Freeze;
    }

    if pty_signal.active {
        return DetectionPolicyDecision::Publish(AgentDetection {
            state: AgentState::Working,
            skip_state_update: false,
            visible_blocker: false,
            visible_working: false,
        });
    }

    DetectionPolicyDecision::Publish(screen_blocked_or_idle_fallback(input.screen_detection))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn detection(state: AgentState) -> AgentDetection {
        AgentDetection {
            state,
            skip_state_update: false,
            visible_blocker: false,
            visible_working: state == AgentState::Working,
        }
    }

    fn input(screen_detection: AgentDetection) -> DetectionPolicyInput {
        DetectionPolicyInput {
            agent: Some(Agent::Codex),
            screen_detection,
            process_exited: false,
            startup_grace_active: false,
            pty_signal: Some(PtySignal {
                active: false,
                tainted: false,
            }),
        }
    }

    #[test]
    fn classifies_full_lifecycle_hook_sources() {
        assert!(full_lifecycle_hook_authority("herdr:pi", "pi"));
        assert!(full_lifecycle_hook_authority("herdr:omp", "omp"));
        assert!(full_lifecycle_hook_authority("herdr:hermes", "hermes"));
        assert!(full_lifecycle_hook_authority("herdr:opencode", "opencode"));
        assert!(full_lifecycle_hook_authority("herdr:kilo", "kilo"));
        assert!(!full_lifecycle_hook_authority("herdr:copilot", "copilot"));
        assert!(!full_lifecycle_hook_authority("herdr:codex", "codex"));
        assert!(!full_lifecycle_hook_authority("herdr:claude", "claude"));
        assert!(!full_lifecycle_hook_authority("herdr:cursor", "cursor"));
        assert!(!full_lifecycle_hook_authority("herdr:kimi", "kimi"));
        assert!(!full_lifecycle_hook_authority("herdr:droid", "droid"));
        assert!(!full_lifecycle_hook_authority("herdr:qodercli", "qodercli"));
        assert!(!full_lifecycle_hook_authority("custom", "pi"));
    }

    #[test]
    fn classifies_full_lifecycle_detected_agents_without_omp_variant() {
        assert!(full_lifecycle_detected_agent(Agent::Pi));
        assert!(full_lifecycle_detected_agent(Agent::Hermes));
        assert!(full_lifecycle_detected_agent(Agent::OpenCode));
        assert!(full_lifecycle_detected_agent(Agent::Kilo));
        assert!(!full_lifecycle_detected_agent(Agent::GithubCopilot));
        assert!(!full_lifecycle_detected_agent(Agent::Kimi));
        assert!(!full_lifecycle_detected_agent(Agent::Droid));
        assert!(!full_lifecycle_detected_agent(Agent::Qodercli));
        assert!(!full_lifecycle_detected_agent(Agent::Codex));
        assert!(!full_lifecycle_detected_agent(Agent::Claude));
    }

    #[test]
    fn startup_grace_freezes_publish() {
        let mut input = input(detection(AgentState::Working));
        input.startup_grace_active = true;

        assert_eq!(
            apply_detection_policy(input),
            DetectionPolicyDecision::Freeze
        );
    }

    #[test]
    fn taint_freezes_weak_publish() {
        let mut input = input(detection(AgentState::Idle));
        input.pty_signal = Some(PtySignal {
            active: false,
            tainted: true,
        });

        assert_eq!(
            apply_detection_policy(input),
            DetectionPolicyDecision::Freeze
        );
    }

    #[test]
    fn taint_freezes_visible_blocker_until_pty_is_quiet() {
        let mut blocker = detection(AgentState::Blocked);
        blocker.visible_blocker = true;
        let mut input = input(blocker);
        input.pty_signal = Some(PtySignal {
            active: false,
            tainted: true,
        });

        assert_eq!(
            apply_detection_policy(input),
            DetectionPolicyDecision::Freeze
        );
    }

    #[test]
    fn process_exit_publishes_even_during_taint() {
        let mut input = input(detection(AgentState::Idle));
        input.process_exited = true;
        input.pty_signal = Some(PtySignal {
            active: true,
            tainted: true,
        });

        assert_eq!(
            apply_detection_policy(input),
            DetectionPolicyDecision::Publish(detection(AgentState::Idle))
        );
    }

    #[test]
    fn pty_activity_publishes_working_without_inventing_visible_working() {
        let mut input = input(detection(AgentState::Idle));
        input.pty_signal = Some(PtySignal {
            active: true,
            tainted: false,
        });

        assert_eq!(
            apply_detection_policy(input),
            DetectionPolicyDecision::Publish(AgentDetection {
                state: AgentState::Working,
                skip_state_update: false,
                visible_blocker: false,
                visible_working: false,
            })
        );
    }

    #[test]
    fn active_pty_wins_over_visible_blocker() {
        let mut blocker = detection(AgentState::Blocked);
        blocker.visible_blocker = true;
        let mut input = input(blocker);
        input.pty_signal = Some(PtySignal {
            active: true,
            tainted: false,
        });

        assert_eq!(
            apply_detection_policy(input),
            DetectionPolicyDecision::Publish(AgentDetection {
                state: AgentState::Working,
                skip_state_update: false,
                visible_blocker: false,
                visible_working: false,
            })
        );
    }

    #[test]
    fn silent_pty_with_visible_blocker_publishes_blocked() {
        let mut screen = detection(AgentState::Blocked);
        screen.visible_blocker = true;
        let input = input(screen);

        assert_eq!(
            apply_detection_policy(input),
            DetectionPolicyDecision::Publish(AgentDetection {
                state: AgentState::Blocked,
                skip_state_update: false,
                visible_blocker: true,
                visible_working: false,
            })
        );
    }

    #[test]
    fn silent_pty_downgrades_screen_working_to_idle() {
        let input = input(detection(AgentState::Working));

        assert_eq!(
            apply_detection_policy(input),
            DetectionPolicyDecision::Publish(AgentDetection {
                state: AgentState::Idle,
                skip_state_update: false,
                visible_blocker: false,
                visible_working: false,
            })
        );
    }

    #[test]
    fn silent_pty_downgrades_weak_screen_blocked_to_idle() {
        let input = input(detection(AgentState::Blocked));

        assert_eq!(
            apply_detection_policy(input),
            DetectionPolicyDecision::Publish(AgentDetection {
                state: AgentState::Idle,
                skip_state_update: false,
                visible_blocker: false,
                visible_working: false,
            })
        );
    }
}
