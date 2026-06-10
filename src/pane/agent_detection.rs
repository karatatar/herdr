use std::sync::atomic::{AtomicU64, Ordering};

use crate::detect::{Agent, AgentDetection, AgentState};

pub(super) const AGENT_PTY_ACTIVITY_WINDOW: std::time::Duration =
    std::time::Duration::from_millis(1800);
pub(super) const AGENT_INPUT_TAINT_WINDOW: std::time::Duration =
    std::time::Duration::from_millis(1200);
pub(super) const AGENT_POST_TAINT_WORKING_LEASE: std::time::Duration = AGENT_PTY_ACTIVITY_WINDOW;
pub(super) const AGENT_PENDING_IDLE_RECHECK: std::time::Duration =
    std::time::Duration::from_millis(100);
const AGENT_PENDING_IDLE_CONFIRMATIONS: u8 = 3;
pub(super) const AGENT_PENDING_IDLE_CAP: std::time::Duration =
    std::time::Duration::from_millis(700);
pub(super) const AGENT_PENDING_WORKING_FAST_RECHECK: std::time::Duration =
    std::time::Duration::from_millis(100);
const AGENT_PENDING_WORKING_SLOW_RECHECK: std::time::Duration =
    std::time::Duration::from_millis(250);
const AGENT_PENDING_WORKING_FAST_WINDOW: std::time::Duration =
    std::time::Duration::from_millis(500);
pub(super) const AGENT_PENDING_WORKING_CAP: std::time::Duration = std::time::Duration::from_secs(2);
pub(super) const AGENT_PENDING_WORKING_CONFIRM_DELAY: std::time::Duration =
    std::time::Duration::from_millis(250);
pub(super) const STABLE_VISIBLE_SIGNAL_REFRESH: std::time::Duration =
    std::time::Duration::from_millis(800);
pub(super) const AGENT_STARTUP_GRACE_WINDOW: std::time::Duration =
    std::time::Duration::from_secs(3);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct DetectionPublishState {
    pub(super) state: AgentState,
    pub(super) visible_blocker: bool,
    pub(super) visible_working: bool,
}

#[derive(Debug, Default)]
pub(super) struct PendingIdleConfirmation {
    started_at: Option<std::time::Instant>,
    confirmations: u8,
}

impl PendingIdleConfirmation {
    pub(super) fn active(&self) -> bool {
        self.started_at.is_some()
    }

    pub(super) fn clear(&mut self) {
        self.started_at = None;
        self.confirmations = 0;
    }

    pub(super) fn should_hold_working_to_idle(
        &mut self,
        previous: DetectionPublishState,
        next: DetectionPublishState,
        agent_changed: bool,
        process_exited: bool,
        pty_signal: Option<PtyActivitySignal>,
        now: std::time::Instant,
    ) -> bool {
        let is_working_to_plain_idle = previous.state == AgentState::Working
            && next.state == AgentState::Idle
            && !next.visible_blocker
            && !agent_changed
            && !process_exited;

        if !is_working_to_plain_idle {
            self.clear();
            return false;
        }

        if pty_signal.is_some_and(|signal| !signal.active && !signal.tainted) {
            self.clear();
            return false;
        }

        let Some(started_at) = self.started_at else {
            self.started_at = Some(now);
            self.confirmations = 0;
            return true;
        };

        if now.duration_since(started_at) >= AGENT_PENDING_IDLE_CAP {
            self.clear();
            return false;
        }

        self.confirmations = self.confirmations.saturating_add(1);
        if self.confirmations >= AGENT_PENDING_IDLE_CONFIRMATIONS {
            self.clear();
            return false;
        }

        true
    }
}

#[derive(Debug, Default)]
pub(super) struct PendingWorkingConfirmation {
    started_at: Option<std::time::Instant>,
    last_observed_output_seq: u64,
}

impl PendingWorkingConfirmation {
    pub(super) fn active(&self) -> bool {
        self.started_at.is_some()
    }

    pub(super) fn clear(&mut self) {
        self.started_at = None;
        self.last_observed_output_seq = 0;
    }

    pub(super) fn recheck_delay(&self, now: std::time::Instant) -> std::time::Duration {
        let Some(started_at) = self.started_at else {
            return AGENT_PENDING_WORKING_FAST_RECHECK;
        };
        if now.duration_since(started_at) < AGENT_PENDING_WORKING_FAST_WINDOW {
            AGENT_PENDING_WORKING_FAST_RECHECK
        } else {
            AGENT_PENDING_WORKING_SLOW_RECHECK
        }
    }

    pub(super) fn should_hold_idle_to_working(
        &mut self,
        previous: DetectionPublishState,
        next: DetectionPublishState,
        agent_changed: bool,
        process_exited: bool,
        pty_signal: Option<PtyActivitySignal>,
        now: std::time::Instant,
    ) -> bool {
        let is_idle_to_working = previous.state == AgentState::Idle
            && next.state == AgentState::Working
            && !next.visible_blocker
            && !agent_changed
            && !process_exited;

        if !is_idle_to_working {
            self.clear();
            return false;
        }

        let Some(pty_signal) = pty_signal else {
            self.clear();
            return false;
        };
        if !pty_signal.active {
            self.clear();
            return false;
        }

        let Some(started_at) = self.started_at else {
            self.started_at = Some(now);
            self.last_observed_output_seq = pty_signal.output_seq;
            return true;
        };

        if pty_signal.fresh_output && pty_signal.output_seq != self.last_observed_output_seq {
            self.last_observed_output_seq = pty_signal.output_seq;
            if now.duration_since(started_at) >= AGENT_PENDING_WORKING_CONFIRM_DELAY {
                self.clear();
                return false;
            }
        }

        if now.duration_since(started_at) >= AGENT_PENDING_WORKING_CAP {
            self.clear();
            return true;
        }

        true
    }

    pub(super) fn should_publish_held_working_before_exit(
        &mut self,
        previous: DetectionPublishState,
        next: DetectionPublishState,
        process_exited: bool,
    ) -> bool {
        if self.started_at.is_none()
            || !process_exited
            || previous.state != AgentState::Idle
            || next.state != AgentState::Idle
        {
            return false;
        }

        self.clear();
        true
    }
}

#[derive(Debug, Default)]
pub(super) struct PostTaintWorkingLease {
    until: Option<std::time::Instant>,
}

impl PostTaintWorkingLease {
    pub(super) fn active(&self) -> bool {
        self.until.is_some()
    }

    pub(super) fn start(&mut self, now: std::time::Instant) {
        self.until = Some(now + AGENT_POST_TAINT_WORKING_LEASE);
    }

    pub(super) fn clear(&mut self) {
        self.until = None;
    }

    pub(super) fn should_hold_working_to_idle(
        &mut self,
        previous: DetectionPublishState,
        next: DetectionPublishState,
        agent_changed: bool,
        process_exited: bool,
        pty_signal: Option<PtyActivitySignal>,
        now: std::time::Instant,
    ) -> bool {
        let is_working_to_plain_idle = previous.state == AgentState::Working
            && next.state == AgentState::Idle
            && !next.visible_blocker
            && !agent_changed
            && !process_exited;

        if !is_working_to_plain_idle {
            self.clear();
            return false;
        }

        let Some(pty_signal) = pty_signal else {
            self.clear();
            return false;
        };

        if pty_signal.active || pty_signal.tainted {
            self.clear();
            return false;
        }

        if pty_signal.taint_just_ended {
            self.start(now);
            return true;
        }

        let Some(until) = self.until else {
            return false;
        };

        if now < until {
            return true;
        }

        self.clear();
        false
    }
}

#[derive(Debug, Clone, Copy)]
pub(super) struct IdleScreenScanSkipInput {
    pub(super) state: AgentState,
    pub(super) agent: Option<Agent>,
    pub(super) pending_idle_active: bool,
    pub(super) pending_working_active: bool,
    pub(super) post_taint_working_active: bool,
    pub(super) agent_changed: bool,
    pub(super) process_exited: bool,
    pub(super) pty_signal: Option<PtyActivitySignal>,
    pub(super) last_screen_scan_pty_output_seq: Option<u64>,
}

pub(super) fn should_skip_idle_screen_scan(input: IdleScreenScanSkipInput) -> bool {
    if input.state != AgentState::Idle
        || input.agent.is_none()
        || input.pending_idle_active
        || input.pending_working_active
        || input.post_taint_working_active
        || input.agent_changed
        || input.process_exited
    {
        return false;
    }

    let Some(pty_signal) = input.pty_signal else {
        return false;
    };

    !pty_signal.active
        && !pty_signal.tainted
        && !pty_signal.taint_just_ended
        && input.last_screen_scan_pty_output_seq == Some(pty_signal.output_seq)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DetectionScreenReadDecision {
    Read,
    Skip,
    EvaluatePtyWorking,
    Publish {
        state: AgentState,
        visible_blocker: bool,
        visible_working: bool,
        process_exited: bool,
    },
}

#[derive(Debug, Clone, Copy)]
pub(super) struct DetectionScreenReadInput {
    pub(super) state: AgentState,
    pub(super) agent: Option<Agent>,
    pub(super) pending_idle_active: bool,
    pub(super) pending_working_active: bool,
    pub(super) post_taint_working_active: bool,
    pub(super) agent_changed: bool,
    pub(super) process_exited: bool,
    pub(super) pty_activity: Option<PtyActivitySignal>,
    pub(super) last_screen_scan_pty_output_seq: Option<u64>,
}

fn agent_activity_veto_requires_screen(agent: Option<Agent>) -> bool {
    matches!(agent, Some(Agent::Claude))
}

pub(super) fn decide_detection_screen_read(
    input: DetectionScreenReadInput,
) -> DetectionScreenReadDecision {
    if !input.agent_changed
        && !input.process_exited
        && !input.pending_idle_active
        && !input.post_taint_working_active
        && input.agent.is_some()
        && input
            .pty_activity
            .is_some_and(|signal| signal.active && !signal.tainted)
    {
        return match input.state {
            AgentState::Working => DetectionScreenReadDecision::Skip,
            AgentState::Blocked => DetectionScreenReadDecision::Publish {
                state: AgentState::Working,
                visible_blocker: false,
                visible_working: false,
                process_exited: false,
            },
            AgentState::Idle | AgentState::Unknown
                if agent_activity_veto_requires_screen(input.agent)
                    && !input.pending_working_active =>
            {
                DetectionScreenReadDecision::Read
            }
            AgentState::Idle | AgentState::Unknown => {
                DetectionScreenReadDecision::EvaluatePtyWorking
            }
        };
    }

    if should_skip_idle_screen_scan(IdleScreenScanSkipInput {
        state: input.state,
        agent: input.agent,
        pending_idle_active: input.pending_idle_active,
        pending_working_active: input.pending_working_active,
        post_taint_working_active: input.post_taint_working_active,
        agent_changed: input.agent_changed,
        process_exited: input.process_exited,
        pty_signal: input.pty_activity,
        last_screen_scan_pty_output_seq: input.last_screen_scan_pty_output_seq,
    }) {
        DetectionScreenReadDecision::Skip
    } else {
        DetectionScreenReadDecision::Read
    }
}

pub(super) fn pty_working_transition_is_vetoed(
    agent: Option<Agent>,
    previous: DetectionPublishState,
    next: DetectionPublishState,
    content: &str,
) -> bool {
    previous.state == AgentState::Idle
        && next.state == AgentState::Working
        && !next.visible_blocker
        && crate::detect::agent_activity_veto(agent, content).is_some()
}

pub(super) fn should_publish_detection_update(
    previous: DetectionPublishState,
    next: DetectionPublishState,
    agent_changed: bool,
    process_exited: bool,
    stable_visible_signal_refresh_due: bool,
) -> bool {
    next.state != previous.state
        || next.visible_blocker != previous.visible_blocker
        || next.visible_working != previous.visible_working
        || agent_changed
        || process_exited
        || (stable_visible_signal_refresh_due && next.visible_blocker && previous.visible_blocker)
}

pub(super) fn stable_visible_signal_refresh_due(
    previous: DetectionPublishState,
    next: DetectionPublishState,
    last_refresh: Option<std::time::Instant>,
    now: std::time::Instant,
) -> bool {
    let stable_visible_signal = next.visible_blocker && previous.visible_blocker;

    stable_visible_signal
        && last_refresh.is_none_or(|last_refresh| {
            now.duration_since(last_refresh) >= STABLE_VISIBLE_SIGNAL_REFRESH
        })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DetectionTransitionDecision {
    NoPublish,
    PublishHeldWorkingBeforeExit,
    PublishNext,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct DetectionTransitionInput<'a> {
    pub(super) agent: Option<Agent>,
    pub(super) previous_publish: DetectionPublishState,
    pub(super) next_publish: DetectionPublishState,
    pub(super) agent_changed: bool,
    pub(super) process_exited: bool,
    pub(super) pty_activity: Option<PtyActivitySignal>,
    pub(super) stable_refresh_due: bool,
    pub(super) content: &'a str,
    pub(super) now: std::time::Instant,
}

pub(super) fn decide_detection_transition(
    input: DetectionTransitionInput<'_>,
    pending_idle: &mut PendingIdleConfirmation,
    pending_working: &mut PendingWorkingConfirmation,
    post_taint_working: &mut PostTaintWorkingLease,
) -> DetectionTransitionDecision {
    if pty_working_transition_is_vetoed(
        input.agent,
        input.previous_publish,
        input.next_publish,
        input.content,
    ) {
        pending_idle.clear();
        pending_working.clear();
        post_taint_working.clear();
        return DetectionTransitionDecision::NoPublish;
    }

    if pending_working.should_publish_held_working_before_exit(
        input.previous_publish,
        input.next_publish,
        input.process_exited,
    ) {
        pending_idle.clear();
        post_taint_working.clear();
        return DetectionTransitionDecision::PublishHeldWorkingBeforeExit;
    }

    if pending_working.should_hold_idle_to_working(
        input.previous_publish,
        input.next_publish,
        input.agent_changed,
        input.process_exited,
        input.pty_activity,
        input.now,
    ) {
        pending_idle.clear();
        post_taint_working.clear();
        return DetectionTransitionDecision::NoPublish;
    }

    if post_taint_working.should_hold_working_to_idle(
        input.previous_publish,
        input.next_publish,
        input.agent_changed,
        input.process_exited,
        input.pty_activity,
        input.now,
    ) {
        pending_idle.clear();
        pending_working.clear();
        return DetectionTransitionDecision::NoPublish;
    }

    if pending_idle.should_hold_working_to_idle(
        input.previous_publish,
        input.next_publish,
        input.agent_changed,
        input.process_exited,
        input.pty_activity,
        input.now,
    ) {
        pending_working.clear();
        post_taint_working.clear();
        return DetectionTransitionDecision::NoPublish;
    }

    if should_publish_detection_update(
        input.previous_publish,
        input.next_publish,
        input.agent_changed,
        input.process_exited,
        input.stable_refresh_due,
    ) {
        return DetectionTransitionDecision::PublishNext;
    }

    DetectionTransitionDecision::NoPublish
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DetectionPublishDecision {
    NoPublish,
    Publish {
        state: AgentState,
        visible_blocker: bool,
        visible_working: bool,
        process_exited: bool,
    },
}

#[derive(Debug, Clone, Copy)]
pub(super) struct ScreenDetectionPublishInput<'a> {
    pub(super) agent: Option<Agent>,
    pub(super) current_state: AgentState,
    pub(super) last_visible_blocker: bool,
    pub(super) last_visible_working: bool,
    pub(super) last_visible_signal_refresh: Option<std::time::Instant>,
    pub(super) screen_detection: AgentDetection,
    pub(super) process_exited: bool,
    pub(super) agent_changed: bool,
    pub(super) pty_activity: Option<PtyActivitySignal>,
    pub(super) content: &'a str,
    pub(super) now: std::time::Instant,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct PtyWorkingPublishInput {
    pub(super) agent: Option<Agent>,
    pub(super) current_state: AgentState,
    pub(super) last_visible_blocker: bool,
    pub(super) last_visible_working: bool,
    pub(super) last_visible_signal_refresh: Option<std::time::Instant>,
    pub(super) pty_activity: Option<PtyActivitySignal>,
    pub(super) now: std::time::Instant,
}

pub(super) fn decide_pty_working_publish_without_screen(
    input: PtyWorkingPublishInput,
    pending_idle: &mut PendingIdleConfirmation,
    pending_working: &mut PendingWorkingConfirmation,
    post_taint_working: &mut PostTaintWorkingLease,
) -> DetectionPublishDecision {
    let previous_publish = DetectionPublishState {
        state: input.current_state,
        visible_blocker: input.last_visible_blocker,
        visible_working: input.last_visible_working,
    };
    let next_publish = DetectionPublishState {
        state: AgentState::Working,
        visible_blocker: false,
        visible_working: false,
    };
    let stable_refresh_due = stable_visible_signal_refresh_due(
        previous_publish,
        next_publish,
        input.last_visible_signal_refresh,
        input.now,
    );

    match decide_detection_transition(
        DetectionTransitionInput {
            agent: input.agent,
            previous_publish,
            next_publish,
            agent_changed: false,
            process_exited: false,
            pty_activity: input.pty_activity,
            stable_refresh_due,
            content: "",
            now: input.now,
        },
        pending_idle,
        pending_working,
        post_taint_working,
    ) {
        DetectionTransitionDecision::NoPublish => DetectionPublishDecision::NoPublish,
        DetectionTransitionDecision::PublishHeldWorkingBeforeExit => {
            DetectionPublishDecision::Publish {
                state: AgentState::Working,
                visible_blocker: false,
                visible_working: false,
                process_exited: false,
            }
        }
        DetectionTransitionDecision::PublishNext => DetectionPublishDecision::Publish {
            state: AgentState::Working,
            visible_blocker: false,
            visible_working: false,
            process_exited: false,
        },
    }
}

pub(super) fn decide_screen_detection_publish(
    input: ScreenDetectionPublishInput<'_>,
    pending_idle: &mut PendingIdleConfirmation,
    pending_working: &mut PendingWorkingConfirmation,
    post_taint_working: &mut PostTaintWorkingLease,
) -> DetectionPublishDecision {
    let pty_signal = input
        .pty_activity
        .map(|signal| crate::agent_detection_policy::PtySignal {
            active: signal.active,
            tainted: signal.tainted,
        });
    let detection = match crate::agent_detection_policy::apply_detection_policy(
        crate::agent_detection_policy::DetectionPolicyInput {
            agent: input.agent,
            screen_detection: input.screen_detection,
            process_exited: input.process_exited,
            startup_grace_active: false,
            pty_signal,
        },
    ) {
        crate::agent_detection_policy::DetectionPolicyDecision::Publish(detection) => detection,
        crate::agent_detection_policy::DetectionPolicyDecision::Freeze => {
            pending_idle.clear();
            pending_working.clear();
            post_taint_working.clear();
            return DetectionPublishDecision::NoPublish;
        }
    };
    let new_state = crate::terminal::state::stabilize_agent_detection(detection);
    let visible_blocker = detection.visible_blocker && new_state == AgentState::Blocked;
    let visible_working = detection.visible_working && new_state == AgentState::Working;

    let previous_publish = DetectionPublishState {
        state: input.current_state,
        visible_blocker: input.last_visible_blocker,
        visible_working: input.last_visible_working,
    };
    let next_publish = DetectionPublishState {
        state: new_state,
        visible_blocker,
        visible_working,
    };
    let stable_refresh_due = stable_visible_signal_refresh_due(
        previous_publish,
        next_publish,
        input.last_visible_signal_refresh,
        input.now,
    );

    match decide_detection_transition(
        DetectionTransitionInput {
            agent: input.agent,
            previous_publish,
            next_publish,
            agent_changed: input.agent_changed,
            process_exited: input.process_exited,
            pty_activity: input.pty_activity,
            stable_refresh_due,
            content: input.content,
            now: input.now,
        },
        pending_idle,
        pending_working,
        post_taint_working,
    ) {
        DetectionTransitionDecision::NoPublish => DetectionPublishDecision::NoPublish,
        DetectionTransitionDecision::PublishHeldWorkingBeforeExit => {
            DetectionPublishDecision::Publish {
                state: AgentState::Working,
                visible_blocker: false,
                visible_working: false,
                process_exited: false,
            }
        }
        DetectionTransitionDecision::PublishNext => DetectionPublishDecision::Publish {
            state: new_state,
            visible_blocker,
            visible_working,
            process_exited: input.process_exited,
        },
    }
}

pub(super) fn detection_update_for_publish(
    agent: Option<Agent>,
    content: &str,
    process_exited: bool,
) -> Option<crate::detect::AgentDetection> {
    if crate::detect::should_skip_state_update(agent, content) {
        return None;
    }

    if process_exited {
        return Some(crate::detect::AgentDetection {
            state: AgentState::Idle,
            skip_state_update: false,
            visible_blocker: false,
            visible_working: false,
        });
    }

    let detection = crate::detect::detect_agent(agent, content);
    (!detection.skip_state_update).then_some(detection)
}

#[derive(Debug, Default)]
pub(super) struct PtyCausalityTracker {
    last_pty_output_seq: u64,
    last_input_seq: u64,
    input_tainted_until: Option<std::time::Instant>,
    last_agent_pty_at: Option<std::time::Instant>,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct PtyActivitySignal {
    pub(super) active: bool,
    pub(super) tainted: bool,
    pub(super) taint_just_ended: bool,
    pub(super) fresh_output: bool,
    pub(super) output_seq: u64,
}

pub(super) fn baseline_pty_causality(
    tracker: &mut PtyCausalityTracker,
    pty_output_seq: u64,
    input_seq: u64,
) {
    tracker.last_pty_output_seq = pty_output_seq;
    tracker.last_input_seq = input_seq;
    tracker.input_tainted_until = None;
    tracker.last_agent_pty_at = None;
}

pub(super) fn agent_caused_pty_activity_active(
    pty_output_seq: u64,
    input_seq: u64,
    tracker: &mut PtyCausalityTracker,
    now: std::time::Instant,
) -> PtyActivitySignal {
    if input_seq != tracker.last_input_seq {
        tracker.last_input_seq = input_seq;
        tracker.input_tainted_until = Some(now + AGENT_INPUT_TAINT_WINDOW);
        tracker.last_agent_pty_at = None;
    }

    let mut taint_just_ended = false;
    let tainted = match tracker.input_tainted_until {
        Some(until) if now < until => true,
        Some(_) => {
            tracker.input_tainted_until = None;
            taint_just_ended = true;
            false
        }
        None => false,
    };

    let mut fresh_output = false;
    if pty_output_seq != tracker.last_pty_output_seq {
        tracker.last_pty_output_seq = pty_output_seq;
        if !tainted {
            tracker.last_agent_pty_at = Some(now);
            fresh_output = true;
        }
    }

    if tainted {
        return PtyActivitySignal {
            active: false,
            tainted: true,
            taint_just_ended: false,
            fresh_output: false,
            output_seq: tracker.last_pty_output_seq,
        };
    }

    let active = tracker
        .last_agent_pty_at
        .is_some_and(|last| now.duration_since(last) < AGENT_PTY_ACTIVITY_WINDOW);
    PtyActivitySignal {
        active,
        tainted: false,
        taint_just_ended,
        fresh_output,
        output_seq: tracker.last_pty_output_seq,
    }
}

pub(super) fn observe_pty_output_activity(bytes: &[u8], pty_output_seq: &AtomicU64) {
    if !bytes.is_empty() {
        pty_output_seq.fetch_add(1, Ordering::Relaxed);
    }
}

fn consume_skipped_pty_causality(
    tracker: &mut PtyCausalityTracker,
    pty_output_seq: u64,
    input_seq: u64,
) {
    baseline_pty_causality(tracker, pty_output_seq, input_seq);
}

pub(super) fn handle_skipped_detection_update(
    state: AgentState,
    pty_signal: Option<PtyActivitySignal>,
    post_taint_working: &mut PostTaintWorkingLease,
    tracker: &mut PtyCausalityTracker,
    pty_output_seq: u64,
    input_seq: u64,
    now: std::time::Instant,
) {
    if state == AgentState::Working {
        if pty_signal.is_some_and(|signal| signal.taint_just_ended) {
            post_taint_working.start(now);
        }
        return;
    }

    post_taint_working.clear();
    consume_skipped_pty_causality(tracker, pty_output_seq, input_seq);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn publish_state(state: AgentState) -> DetectionPublishState {
        DetectionPublishState {
            state,
            visible_blocker: false,
            visible_working: false,
        }
    }

    fn pty_activity(active: bool, fresh_output: bool, output_seq: u64) -> PtyActivitySignal {
        PtyActivitySignal {
            active,
            tainted: false,
            taint_just_ended: false,
            fresh_output,
            output_seq,
        }
    }

    fn pty_activity_after_taint(output_seq: u64) -> PtyActivitySignal {
        PtyActivitySignal {
            active: false,
            tainted: false,
            taint_just_ended: true,
            fresh_output: false,
            output_seq,
        }
    }

    fn tainted_pty_activity(output_seq: u64) -> PtyActivitySignal {
        PtyActivitySignal {
            active: false,
            tainted: true,
            taint_just_ended: false,
            fresh_output: false,
            output_seq,
        }
    }

    fn transition_input(
        previous_publish: DetectionPublishState,
        next_publish: DetectionPublishState,
        pty_activity: Option<PtyActivitySignal>,
        now: std::time::Instant,
    ) -> DetectionTransitionInput<'static> {
        DetectionTransitionInput {
            agent: Some(Agent::Codex),
            previous_publish,
            next_publish,
            agent_changed: false,
            process_exited: false,
            pty_activity,
            stable_refresh_due: false,
            content: "",
            now,
        }
    }

    fn screen_detection(state: AgentState) -> AgentDetection {
        AgentDetection {
            state,
            skip_state_update: false,
            visible_blocker: false,
            visible_working: state == AgentState::Working,
        }
    }

    fn screen_publish_input(
        current_state: AgentState,
        screen_detection: AgentDetection,
        pty_activity: Option<PtyActivitySignal>,
        now: std::time::Instant,
    ) -> ScreenDetectionPublishInput<'static> {
        ScreenDetectionPublishInput {
            agent: Some(Agent::Codex),
            current_state,
            last_visible_blocker: false,
            last_visible_working: false,
            last_visible_signal_refresh: None,
            screen_detection,
            process_exited: false,
            agent_changed: false,
            pty_activity,
            content: "",
            now,
        }
    }

    fn screen_read_input(
        state: AgentState,
        pty_activity: PtyActivitySignal,
    ) -> DetectionScreenReadInput {
        screen_read_input_for_agent(Some(Agent::Codex), state, pty_activity)
    }

    fn screen_read_input_for_agent(
        agent: Option<Agent>,
        state: AgentState,
        pty_activity: PtyActivitySignal,
    ) -> DetectionScreenReadInput {
        DetectionScreenReadInput {
            state,
            agent,
            pending_idle_active: false,
            pending_working_active: false,
            post_taint_working_active: false,
            agent_changed: false,
            process_exited: false,
            pty_activity: Some(pty_activity),
            last_screen_scan_pty_output_seq: Some(10),
        }
    }

    #[test]
    fn screen_read_decision_skips_only_stable_idle_quiet_output() {
        assert_eq!(
            decide_detection_screen_read(screen_read_input(
                AgentState::Idle,
                pty_activity(false, false, 10),
            )),
            DetectionScreenReadDecision::Skip
        );

        assert_eq!(
            decide_detection_screen_read(screen_read_input(
                AgentState::Idle,
                pty_activity(false, false, 11),
            )),
            DetectionScreenReadDecision::Read
        );
        assert_eq!(
            decide_detection_screen_read(screen_read_input(
                AgentState::Idle,
                pty_activity(true, true, 10),
            )),
            DetectionScreenReadDecision::EvaluatePtyWorking
        );
        assert_eq!(
            decide_detection_screen_read(screen_read_input(
                AgentState::Working,
                pty_activity(false, false, 10),
            )),
            DetectionScreenReadDecision::Read
        );
    }

    #[test]
    fn screen_read_decision_handles_active_pty_without_screen_for_non_idle_states() {
        assert_eq!(
            decide_detection_screen_read(screen_read_input(
                AgentState::Working,
                pty_activity(true, true, 11),
            )),
            DetectionScreenReadDecision::Skip
        );

        assert_eq!(
            decide_detection_screen_read(screen_read_input(
                AgentState::Blocked,
                pty_activity(true, true, 11),
            )),
            DetectionScreenReadDecision::Publish {
                state: AgentState::Working,
                visible_blocker: false,
                visible_working: false,
                process_exited: false,
            }
        );

        assert_eq!(
            decide_detection_screen_read(screen_read_input(
                AgentState::Idle,
                pty_activity(true, true, 11),
            )),
            DetectionScreenReadDecision::EvaluatePtyWorking
        );

        assert_eq!(
            decide_detection_screen_read(screen_read_input_for_agent(
                Some(Agent::Claude),
                AgentState::Idle,
                pty_activity(true, true, 11),
            )),
            DetectionScreenReadDecision::Read
        );
    }

    #[test]
    fn screen_read_decision_reads_during_pending_transitions() {
        let mut input = screen_read_input(AgentState::Idle, pty_activity(false, false, 10));
        input.pending_working_active = true;
        assert_eq!(
            decide_detection_screen_read(input),
            DetectionScreenReadDecision::Read
        );

        let mut input = screen_read_input(AgentState::Idle, pty_activity(false, false, 10));
        input.pending_idle_active = true;
        assert_eq!(
            decide_detection_screen_read(input),
            DetectionScreenReadDecision::Read
        );

        let mut input = screen_read_input(AgentState::Idle, pty_activity(false, false, 10));
        input.post_taint_working_active = true;
        assert_eq!(
            decide_detection_screen_read(input),
            DetectionScreenReadDecision::Read
        );
    }

    #[test]
    fn screen_read_decision_keeps_active_pty_pending_working_screenless() {
        let mut input = screen_read_input(AgentState::Idle, pty_activity(true, true, 11));
        input.pending_working_active = true;
        assert_eq!(
            decide_detection_screen_read(input),
            DetectionScreenReadDecision::EvaluatePtyWorking
        );

        let mut input = screen_read_input_for_agent(
            Some(Agent::Claude),
            AgentState::Idle,
            pty_activity(true, true, 11),
        );
        input.pending_working_active = true;
        assert_eq!(
            decide_detection_screen_read(input),
            DetectionScreenReadDecision::EvaluatePtyWorking
        );
    }

    #[test]
    fn codex_transcript_viewer_suppresses_prompt_idle_publish() {
        let content = "/ T R A N S C R I P T /\n\n› yeah go ahead\n────────────────────────────────────────────────────────────────────────────────── 100% ─\n ↑/↓ to scroll   pgup/pgdn to page   home/end to jump\n q to quit   esc to edit prev";

        assert!(detection_update_for_publish(Some(Agent::Codex), content, false).is_none());
    }

    #[test]
    fn codex_transcript_viewer_suppresses_process_exit_idle_publish() {
        let content = "/ T R A N S C R I P T /\n\n› yeah go ahead\n────────────────────────────────────────────────────────────────────────────────── 100% ─\n ↑/↓ to scroll   pgup/pgdn to page   home/end to jump\n q to quit   esc to edit prev";

        assert!(detection_update_for_publish(Some(Agent::Codex), content, true).is_none());
    }

    #[test]
    fn process_exit_without_transcript_still_reports_idle() {
        let detection =
            detection_update_for_publish(Some(Agent::Codex), "Codex finished\n› ", true)
                .expect("process exit should publish idle outside transcript viewer");

        assert_eq!(detection.state, AgentState::Idle);
        assert!(!detection.skip_state_update);
    }

    #[test]
    fn stable_plain_idle_does_not_republish() {
        let now = std::time::Instant::now();
        let previous = DetectionPublishState {
            state: AgentState::Idle,
            visible_blocker: false,
            visible_working: false,
        };
        let refresh_due = stable_visible_signal_refresh_due(
            previous,
            previous,
            Some(now - STABLE_VISIBLE_SIGNAL_REFRESH),
            now,
        );

        assert!(!should_publish_detection_update(
            previous,
            previous,
            false,
            false,
            refresh_due
        ));
    }

    #[test]
    fn stable_visible_working_does_not_republish() {
        let now = std::time::Instant::now();
        let previous = DetectionPublishState {
            state: AgentState::Working,
            visible_blocker: false,
            visible_working: true,
        };
        let refresh_due = stable_visible_signal_refresh_due(
            previous,
            previous,
            Some(now - STABLE_VISIBLE_SIGNAL_REFRESH),
            now,
        );

        assert!(!should_publish_detection_update(
            previous,
            previous,
            false,
            false,
            refresh_due
        ));
    }

    #[test]
    fn stable_visible_blocker_republishes_for_hook_override_refresh() {
        let now = std::time::Instant::now();
        let previous = DetectionPublishState {
            state: AgentState::Blocked,
            visible_blocker: true,
            visible_working: false,
        };
        let refresh_due = stable_visible_signal_refresh_due(
            previous,
            previous,
            Some(now - STABLE_VISIBLE_SIGNAL_REFRESH),
            now,
        );

        assert!(should_publish_detection_update(
            previous,
            previous,
            false,
            false,
            refresh_due
        ));
    }

    #[test]
    fn pending_idle_holds_working_to_plain_idle_until_confirmed() {
        let now = std::time::Instant::now();
        let previous = publish_state(AgentState::Working);
        let next = publish_state(AgentState::Idle);
        let mut pending = PendingIdleConfirmation::default();

        assert!(pending.should_hold_working_to_idle(previous, next, false, false, None, now));
        assert!(pending.should_hold_working_to_idle(
            previous,
            next,
            false,
            false,
            None,
            now + AGENT_PENDING_IDLE_RECHECK
        ));
        assert!(pending.should_hold_working_to_idle(
            previous,
            next,
            false,
            false,
            None,
            now + AGENT_PENDING_IDLE_RECHECK * 2
        ));
        assert!(!pending.should_hold_working_to_idle(
            previous,
            next,
            false,
            false,
            None,
            now + AGENT_PENDING_IDLE_RECHECK * 3
        ));
    }

    #[test]
    fn pending_idle_cap_publishes_idle_when_still_quiet() {
        let now = std::time::Instant::now();
        let previous = publish_state(AgentState::Working);
        let next = publish_state(AgentState::Idle);
        let mut pending = PendingIdleConfirmation::default();

        assert!(pending.should_hold_working_to_idle(previous, next, false, false, None, now));
        assert!(!pending.should_hold_working_to_idle(
            previous,
            next,
            false,
            false,
            None,
            now + AGENT_PENDING_IDLE_CAP
        ));
    }

    #[test]
    fn pending_idle_clears_when_work_resumes_or_blocker_appears() {
        let now = std::time::Instant::now();
        let previous = publish_state(AgentState::Working);
        let idle = publish_state(AgentState::Idle);
        let working = publish_state(AgentState::Working);
        let mut blocked = publish_state(AgentState::Blocked);
        blocked.visible_blocker = true;
        let mut pending = PendingIdleConfirmation::default();

        assert!(pending.should_hold_working_to_idle(previous, idle, false, false, None, now));
        assert!(pending.active());
        assert!(!pending.should_hold_working_to_idle(previous, working, false, false, None, now));
        assert!(!pending.active());

        assert!(pending.should_hold_working_to_idle(previous, idle, false, false, None, now));
        assert!(!pending.should_hold_working_to_idle(previous, blocked, false, false, None, now));
        assert!(!pending.active());
    }

    #[test]
    fn pending_idle_does_not_extend_pty_quiet_lease() {
        let now = std::time::Instant::now();
        let previous = publish_state(AgentState::Working);
        let idle = publish_state(AgentState::Idle);
        let mut pending = PendingIdleConfirmation::default();

        assert!(!pending.should_hold_working_to_idle(
            previous,
            idle,
            false,
            false,
            Some(pty_activity(false, false, 10)),
            now
        ));
        assert!(!pending.active());
    }

    #[test]
    fn post_taint_lease_holds_existing_working_before_idle_fallback() {
        let now = std::time::Instant::now();
        let previous = publish_state(AgentState::Working);
        let idle = publish_state(AgentState::Idle);
        let mut lease = PostTaintWorkingLease::default();

        assert!(lease.should_hold_working_to_idle(
            previous,
            idle,
            false,
            false,
            Some(pty_activity_after_taint(10)),
            now
        ));
        assert!(lease.should_hold_working_to_idle(
            previous,
            idle,
            false,
            false,
            Some(pty_activity(false, false, 10)),
            now + AGENT_POST_TAINT_WORKING_LEASE - std::time::Duration::from_millis(1)
        ));
        assert!(!lease.should_hold_working_to_idle(
            previous,
            idle,
            false,
            false,
            Some(pty_activity(false, false, 10)),
            now + AGENT_POST_TAINT_WORKING_LEASE + std::time::Duration::from_millis(1)
        ));
    }

    #[test]
    fn post_taint_lease_does_not_create_idle_to_working() {
        let now = std::time::Instant::now();
        let idle = publish_state(AgentState::Idle);
        let working = publish_state(AgentState::Working);
        let mut lease = PostTaintWorkingLease::default();

        assert!(!lease.should_hold_working_to_idle(
            idle,
            working,
            false,
            false,
            Some(pty_activity_after_taint(10)),
            now
        ));
    }

    fn idle_scan_skip_input(
        state: AgentState,
        pty_signal: PtyActivitySignal,
    ) -> IdleScreenScanSkipInput {
        IdleScreenScanSkipInput {
            state,
            agent: Some(Agent::Codex),
            pending_idle_active: false,
            pending_working_active: false,
            post_taint_working_active: false,
            agent_changed: false,
            process_exited: false,
            pty_signal: Some(pty_signal),
            last_screen_scan_pty_output_seq: Some(10),
        }
    }

    #[test]
    fn idle_screen_scan_skip_accepts_only_idle_same_quiet_output() {
        assert!(should_skip_idle_screen_scan(idle_scan_skip_input(
            AgentState::Idle,
            pty_activity(false, false, 10)
        )));

        assert!(!should_skip_idle_screen_scan(idle_scan_skip_input(
            AgentState::Idle,
            pty_activity(false, false, 11)
        )));
        assert!(!should_skip_idle_screen_scan(idle_scan_skip_input(
            AgentState::Idle,
            pty_activity(true, true, 10)
        )));
        assert!(!should_skip_idle_screen_scan(idle_scan_skip_input(
            AgentState::Idle,
            tainted_pty_activity(10)
        )));
        assert!(!should_skip_idle_screen_scan(idle_scan_skip_input(
            AgentState::Working,
            pty_activity(false, false, 10)
        )));
        assert!(!should_skip_idle_screen_scan(idle_scan_skip_input(
            AgentState::Blocked,
            pty_activity(false, false, 10)
        )));
        assert!(!should_skip_idle_screen_scan(idle_scan_skip_input(
            AgentState::Idle,
            pty_activity_after_taint(10)
        )));
    }

    #[test]
    fn idle_screen_scan_skip_respects_transitions_and_missing_agent() {
        let mut input = idle_scan_skip_input(AgentState::Idle, pty_activity(false, false, 10));
        input.pending_working_active = true;
        assert!(!should_skip_idle_screen_scan(input));

        let mut input = idle_scan_skip_input(AgentState::Idle, pty_activity(false, false, 10));
        input.pending_idle_active = true;
        assert!(!should_skip_idle_screen_scan(input));

        let mut input = idle_scan_skip_input(AgentState::Idle, pty_activity(false, false, 10));
        input.post_taint_working_active = true;
        assert!(!should_skip_idle_screen_scan(input));

        let mut input = idle_scan_skip_input(AgentState::Idle, pty_activity(false, false, 10));
        input.agent_changed = true;
        assert!(!should_skip_idle_screen_scan(input));

        let mut input = idle_scan_skip_input(AgentState::Idle, pty_activity(false, false, 10));
        input.process_exited = true;
        assert!(!should_skip_idle_screen_scan(input));

        let mut input = idle_scan_skip_input(AgentState::Idle, pty_activity(false, false, 10));
        input.agent = None;
        assert!(!should_skip_idle_screen_scan(input));

        let mut input = idle_scan_skip_input(AgentState::Idle, pty_activity(false, false, 10));
        input.pty_signal = None;
        assert!(!should_skip_idle_screen_scan(input));
    }

    #[test]
    fn pending_working_holds_single_twitch_then_clears_when_quiet() {
        let now = std::time::Instant::now();
        let idle = publish_state(AgentState::Idle);
        let working = publish_state(AgentState::Working);
        let mut pending = PendingWorkingConfirmation::default();

        assert!(pending.should_hold_idle_to_working(
            idle,
            working,
            false,
            false,
            Some(pty_activity(true, true, 10)),
            now
        ));
        assert!(pending.active());
        assert!(!pending.should_hold_idle_to_working(
            idle,
            idle,
            false,
            false,
            Some(pty_activity(false, false, 10)),
            now + AGENT_PTY_ACTIVITY_WINDOW
        ));
        assert!(!pending.active());
    }

    #[test]
    fn pending_working_confirms_after_delayed_output_observation() {
        let now = std::time::Instant::now();
        let idle = publish_state(AgentState::Idle);
        let working = publish_state(AgentState::Working);
        let mut pending = PendingWorkingConfirmation::default();

        assert!(pending.should_hold_idle_to_working(
            idle,
            working,
            false,
            false,
            Some(pty_activity(true, true, 10)),
            now
        ));
        assert!(!pending.should_hold_idle_to_working(
            idle,
            working,
            false,
            false,
            Some(pty_activity(true, true, 11)),
            now + AGENT_PENDING_WORKING_CONFIRM_DELAY
        ));
        assert!(!pending.active());
    }

    #[test]
    fn pending_working_counts_raw_sequence_jump_once() {
        let now = std::time::Instant::now();
        let idle = publish_state(AgentState::Idle);
        let working = publish_state(AgentState::Working);
        let mut pending = PendingWorkingConfirmation::default();

        assert!(pending.should_hold_idle_to_working(
            idle,
            working,
            false,
            false,
            Some(pty_activity(true, true, 10)),
            now
        ));
        assert!(pending.should_hold_idle_to_working(
            idle,
            working,
            false,
            false,
            Some(pty_activity(true, true, 14)),
            now + AGENT_PENDING_WORKING_FAST_RECHECK
        ));
        assert!(pending.should_hold_idle_to_working(
            idle,
            working,
            false,
            false,
            Some(pty_activity(true, false, 14)),
            now + AGENT_PENDING_WORKING_FAST_RECHECK * 2
        ));
        assert!(!pending.should_hold_idle_to_working(
            idle,
            working,
            false,
            false,
            Some(pty_activity(true, true, 15)),
            now + AGENT_PENDING_WORKING_CONFIRM_DELAY
        ));
    }

    #[test]
    fn pending_working_cap_suppresses_unconfirmed_activity() {
        let now = std::time::Instant::now();
        let idle = publish_state(AgentState::Idle);
        let working = publish_state(AgentState::Working);
        let mut pending = PendingWorkingConfirmation::default();

        assert!(pending.should_hold_idle_to_working(
            idle,
            working,
            false,
            false,
            Some(pty_activity(true, true, 10)),
            now
        ));
        assert!(pending.should_hold_idle_to_working(
            idle,
            working,
            false,
            false,
            Some(pty_activity(true, true, 11)),
            now + AGENT_PENDING_WORKING_FAST_RECHECK
        ));
        assert!(pending.should_hold_idle_to_working(
            idle,
            working,
            false,
            false,
            Some(pty_activity(true, false, 11)),
            now + AGENT_PENDING_WORKING_CAP
        ));
        assert!(!pending.active());

        assert!(pending.should_hold_idle_to_working(
            idle,
            working,
            false,
            false,
            Some(pty_activity(true, true, 20)),
            now
        ));
        assert!(!pending.should_hold_idle_to_working(
            idle,
            working,
            false,
            false,
            Some(pty_activity(true, true, 21)),
            now + AGENT_PENDING_WORKING_CONFIRM_DELAY
        ));
        assert!(!pending.active());
    }

    #[test]
    fn pending_working_process_exit_publishes_held_working_first() {
        let now = std::time::Instant::now();
        let idle = publish_state(AgentState::Idle);
        let working = publish_state(AgentState::Working);
        let mut pending = PendingWorkingConfirmation::default();

        assert!(pending.should_hold_idle_to_working(
            idle,
            working,
            false,
            false,
            Some(pty_activity(true, true, 10)),
            now
        ));
        assert!(pending.should_publish_held_working_before_exit(idle, idle, true));
        assert!(!pending.active());
    }

    #[test]
    fn pty_activity_distinguishes_fresh_output_from_active_hold() {
        let now = std::time::Instant::now();
        let mut tracker = PtyCausalityTracker::default();
        baseline_pty_causality(&mut tracker, 1, 1);

        let fresh = agent_caused_pty_activity_active(2, 1, &mut tracker, now);
        assert!(fresh.active);
        assert!(fresh.fresh_output);
        assert_eq!(fresh.output_seq, 2);

        let held = agent_caused_pty_activity_active(
            2,
            1,
            &mut tracker,
            now + AGENT_PENDING_WORKING_FAST_RECHECK,
        );
        assert!(held.active);
        assert!(!held.fresh_output);
        assert_eq!(held.output_seq, 2);
    }

    #[test]
    fn pty_activity_lease_survives_sparse_heartbeat_jitter() {
        let now = std::time::Instant::now();
        let mut tracker = PtyCausalityTracker::default();
        baseline_pty_causality(&mut tracker, 1, 1);

        let first = agent_caused_pty_activity_active(2, 1, &mut tracker, now);
        assert!(first.active);
        assert!(first.fresh_output);

        let held_before_next_tick = agent_caused_pty_activity_active(
            2,
            1,
            &mut tracker,
            now + std::time::Duration::from_millis(1700),
        );
        assert!(held_before_next_tick.active);
        assert!(!held_before_next_tick.fresh_output);

        let next_tick = agent_caused_pty_activity_active(
            3,
            1,
            &mut tracker,
            now + std::time::Duration::from_millis(1700),
        );
        assert!(next_tick.active);
        assert!(next_tick.fresh_output);

        let held_after_next_tick = agent_caused_pty_activity_active(
            3,
            1,
            &mut tracker,
            now + std::time::Duration::from_millis(3400),
        );
        assert!(held_after_next_tick.active);

        let expired = agent_caused_pty_activity_active(
            3,
            1,
            &mut tracker,
            now + std::time::Duration::from_millis(3501),
        );
        assert!(!expired.active);
    }

    #[test]
    fn pty_output_activity_tracks_raw_nonempty_reads() {
        let seq = AtomicU64::new(0);

        observe_pty_output_activity(b"", &seq);
        assert_eq!(seq.load(Ordering::Relaxed), 0);

        observe_pty_output_activity(b"\x1b[?2026h", &seq);
        assert_eq!(seq.load(Ordering::Relaxed), 1);

        observe_pty_output_activity(b"body bytes", &seq);
        assert_eq!(seq.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn claude_recap_veto_only_applies_to_idle_to_working() {
        let screen =
            "※ recap: Done. (disable recaps in /config)\n\n─────────────\n❯ \n─────────────";
        let idle = publish_state(AgentState::Idle);
        let working = publish_state(AgentState::Working);

        assert!(pty_working_transition_is_vetoed(
            Some(Agent::Claude),
            idle,
            working,
            screen
        ));
        assert!(!pty_working_transition_is_vetoed(
            Some(Agent::Claude),
            working,
            idle,
            screen
        ));
        assert!(!pty_working_transition_is_vetoed(
            Some(Agent::Codex),
            idle,
            working,
            screen
        ));
    }

    #[test]
    fn pty_activity_outside_taint_reports_active_until_hold_expires() {
        let now = std::time::Instant::now();
        let mut tracker = PtyCausalityTracker::default();
        baseline_pty_causality(&mut tracker, 1, 1);

        let active = agent_caused_pty_activity_active(2, 1, &mut tracker, now);
        assert!(active.active);
        assert!(!active.tainted);

        let held = agent_caused_pty_activity_active(
            2,
            1,
            &mut tracker,
            now + AGENT_PTY_ACTIVITY_WINDOW - std::time::Duration::from_millis(1),
        );
        assert!(held.active);
        assert!(!held.tainted);

        let expired = agent_caused_pty_activity_active(
            2,
            1,
            &mut tracker,
            now + AGENT_PTY_ACTIVITY_WINDOW + std::time::Duration::from_millis(1),
        );
        assert!(!expired.active);
        assert!(!expired.tainted);
    }

    #[test]
    fn input_taint_discards_pty_activity_until_fresh_post_taint_output() {
        let now = std::time::Instant::now();
        let mut tracker = PtyCausalityTracker::default();
        baseline_pty_causality(&mut tracker, 1, 1);

        let tainted = agent_caused_pty_activity_active(2, 2, &mut tracker, now);
        assert!(!tainted.active);
        assert!(tainted.tainted);

        let after_taint = agent_caused_pty_activity_active(
            2,
            2,
            &mut tracker,
            now + AGENT_INPUT_TAINT_WINDOW + std::time::Duration::from_millis(1),
        );
        assert!(!after_taint.active);
        assert!(!after_taint.tainted);
        assert!(after_taint.taint_just_ended);

        let settled = agent_caused_pty_activity_active(
            2,
            2,
            &mut tracker,
            now + AGENT_INPUT_TAINT_WINDOW + std::time::Duration::from_millis(2),
        );
        assert!(!settled.active);
        assert!(!settled.tainted);
        assert!(!settled.taint_just_ended);

        let fresh_output = agent_caused_pty_activity_active(
            3,
            2,
            &mut tracker,
            now + AGENT_INPUT_TAINT_WINDOW + std::time::Duration::from_millis(3),
        );
        assert!(fresh_output.active);
        assert!(!fresh_output.tainted);
    }

    #[test]
    fn skipped_update_consumes_expired_taint_edge() {
        let now = std::time::Instant::now();
        let mut tracker = PtyCausalityTracker::default();
        let mut lease = PostTaintWorkingLease::default();
        baseline_pty_causality(&mut tracker, 1, 1);

        let tainted = agent_caused_pty_activity_active(2, 2, &mut tracker, now);
        assert!(tainted.tainted);

        handle_skipped_detection_update(
            AgentState::Idle,
            Some(tainted),
            &mut lease,
            &mut tracker,
            2,
            2,
            now,
        );

        let after_skip = agent_caused_pty_activity_active(
            2,
            2,
            &mut tracker,
            now + AGENT_INPUT_TAINT_WINDOW + std::time::Duration::from_millis(1),
        );
        assert!(!after_skip.active);
        assert!(!after_skip.tainted);
        assert!(!after_skip.taint_just_ended);
    }

    #[test]
    fn skipped_working_update_starts_post_taint_lease_on_taint_edge() {
        let now = std::time::Instant::now();
        let mut tracker = PtyCausalityTracker::default();
        let mut lease = PostTaintWorkingLease::default();

        handle_skipped_detection_update(
            AgentState::Working,
            Some(pty_activity_after_taint(10)),
            &mut lease,
            &mut tracker,
            10,
            2,
            now,
        );

        let previous = publish_state(AgentState::Working);
        let idle = publish_state(AgentState::Idle);

        assert!(lease.should_hold_working_to_idle(
            previous,
            idle,
            false,
            false,
            Some(pty_activity(false, false, 10)),
            now + std::time::Duration::from_millis(1)
        ));
    }

    #[test]
    fn startup_grace_rebaseline_discards_accumulated_pty_activity() {
        let now = std::time::Instant::now();
        let mut tracker = PtyCausalityTracker::default();
        baseline_pty_causality(&mut tracker, 1, 1);

        let startup_render = agent_caused_pty_activity_active(2, 1, &mut tracker, now);
        assert!(startup_render.active);

        baseline_pty_causality(&mut tracker, 2, 1);
        let after_grace =
            agent_caused_pty_activity_active(2, 1, &mut tracker, now + AGENT_STARTUP_GRACE_WINDOW);

        assert!(!after_grace.active);
        assert!(!after_grace.tainted);
    }

    #[test]
    fn transition_decision_publishes_next_for_plain_state_change() {
        let now = std::time::Instant::now();
        let mut pending_idle = PendingIdleConfirmation::default();
        let mut pending_working = PendingWorkingConfirmation::default();
        let mut post_taint_working = PostTaintWorkingLease::default();
        let mut blocked = publish_state(AgentState::Blocked);
        blocked.visible_blocker = true;

        assert_eq!(
            decide_detection_transition(
                transition_input(
                    publish_state(AgentState::Idle),
                    blocked,
                    Some(pty_activity(false, false, 10)),
                    now,
                ),
                &mut pending_idle,
                &mut pending_working,
                &mut post_taint_working,
            ),
            DetectionTransitionDecision::PublishNext
        );
    }

    #[test]
    fn transition_decision_holds_idle_to_working_pending_confirmation() {
        let now = std::time::Instant::now();
        let mut pending_idle = PendingIdleConfirmation::default();
        let mut pending_working = PendingWorkingConfirmation::default();
        let mut post_taint_working = PostTaintWorkingLease::default();

        assert_eq!(
            decide_detection_transition(
                transition_input(
                    publish_state(AgentState::Idle),
                    publish_state(AgentState::Working),
                    Some(pty_activity(true, true, 10)),
                    now,
                ),
                &mut pending_idle,
                &mut pending_working,
                &mut post_taint_working,
            ),
            DetectionTransitionDecision::NoPublish
        );
        assert!(pending_working.active());
    }

    #[test]
    fn transition_decision_publishes_held_working_before_exit() {
        let now = std::time::Instant::now();
        let mut pending_idle = PendingIdleConfirmation::default();
        let mut pending_working = PendingWorkingConfirmation::default();
        let mut post_taint_working = PostTaintWorkingLease::default();

        assert_eq!(
            decide_detection_transition(
                transition_input(
                    publish_state(AgentState::Idle),
                    publish_state(AgentState::Working),
                    Some(pty_activity(true, true, 10)),
                    now,
                ),
                &mut pending_idle,
                &mut pending_working,
                &mut post_taint_working,
            ),
            DetectionTransitionDecision::NoPublish
        );

        let mut input = transition_input(
            publish_state(AgentState::Idle),
            publish_state(AgentState::Idle),
            Some(pty_activity(false, false, 10)),
            now + std::time::Duration::from_millis(1),
        );
        input.process_exited = true;

        assert_eq!(
            decide_detection_transition(
                input,
                &mut pending_idle,
                &mut pending_working,
                &mut post_taint_working,
            ),
            DetectionTransitionDecision::PublishHeldWorkingBeforeExit
        );
        assert!(!pending_working.active());
    }

    #[test]
    fn transition_decision_holds_working_to_idle_after_taint() {
        let now = std::time::Instant::now();
        let mut pending_idle = PendingIdleConfirmation::default();
        let mut pending_working = PendingWorkingConfirmation::default();
        let mut post_taint_working = PostTaintWorkingLease::default();

        assert_eq!(
            decide_detection_transition(
                transition_input(
                    publish_state(AgentState::Working),
                    publish_state(AgentState::Idle),
                    Some(pty_activity_after_taint(10)),
                    now,
                ),
                &mut pending_idle,
                &mut pending_working,
                &mut post_taint_working,
            ),
            DetectionTransitionDecision::NoPublish
        );
        assert!(post_taint_working.active());
    }

    #[test]
    fn screen_publish_prefers_active_pty_working_over_screen_blocker() {
        let now = std::time::Instant::now();
        let mut pending_idle = PendingIdleConfirmation::default();
        let mut pending_working = PendingWorkingConfirmation::default();
        let mut post_taint_working = PostTaintWorkingLease::default();
        let mut blocked = screen_detection(AgentState::Blocked);
        blocked.visible_blocker = true;

        assert_eq!(
            decide_screen_detection_publish(
                screen_publish_input(
                    AgentState::Blocked,
                    blocked,
                    Some(pty_activity(true, true, 10)),
                    now,
                ),
                &mut pending_idle,
                &mut pending_working,
                &mut post_taint_working,
            ),
            DetectionPublishDecision::Publish {
                state: AgentState::Working,
                visible_blocker: false,
                visible_working: false,
                process_exited: false,
            }
        );
    }

    #[test]
    fn screen_publish_downgrades_visible_working_to_idle_when_pty_is_quiet() {
        let now = std::time::Instant::now();
        let mut pending_idle = PendingIdleConfirmation::default();
        let mut pending_working = PendingWorkingConfirmation::default();
        let mut post_taint_working = PostTaintWorkingLease::default();

        assert_eq!(
            decide_screen_detection_publish(
                screen_publish_input(
                    AgentState::Blocked,
                    screen_detection(AgentState::Working),
                    Some(pty_activity(false, false, 10)),
                    now,
                ),
                &mut pending_idle,
                &mut pending_working,
                &mut post_taint_working,
            ),
            DetectionPublishDecision::Publish {
                state: AgentState::Idle,
                visible_blocker: false,
                visible_working: false,
                process_exited: false,
            }
        );
    }

    #[test]
    fn screen_publish_freezes_during_taint() {
        let now = std::time::Instant::now();
        let mut pending_idle = PendingIdleConfirmation::default();
        let mut pending_working = PendingWorkingConfirmation::default();
        let mut post_taint_working = PostTaintWorkingLease::default();

        assert_eq!(
            decide_screen_detection_publish(
                screen_publish_input(
                    AgentState::Working,
                    screen_detection(AgentState::Idle),
                    Some(PtyActivitySignal {
                        active: false,
                        tainted: true,
                        taint_just_ended: false,
                        fresh_output: false,
                        output_seq: 10,
                    }),
                    now,
                ),
                &mut pending_idle,
                &mut pending_working,
                &mut post_taint_working,
            ),
            DetectionPublishDecision::NoPublish
        );
    }
}
