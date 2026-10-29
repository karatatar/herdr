use std::sync::mpsc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use crossterm::event::{KeyModifiers, MouseEventKind};
use tracing::debug;

use crate::api::schema::{PaneReadResult, ResponseResult, SuccessResponse};
use crate::terminal::{ScreenSnapshot, TerminalId, TerminalRuntime, UpwardMerge};

const INITIAL_QUIET: Duration = Duration::from_millis(10);
const OUTPUT_QUIET: Duration = Duration::from_millis(10);
const STEP_TIMEOUT: Duration = Duration::from_millis(120);
// Fork: long agent transcripts need far more than the upstream 15s/1000 rows.
// The harvest stops earlier once it reaches the top or the requested rows.
const MAX_DURATION: Duration = Duration::from_secs(120);
const MAX_RESTORE_DURATION: Duration = Duration::from_secs(5);
const WHEEL_STEP_EVENTS: usize = 3;
/// Extra step timeouts an unaligned frame may take to finish redrawing before
/// the harvest treats it as an overshoot and starts recovering.
const UNALIGNED_GRACE_STEPS: u8 = 2;
/// Agents such as Claude Code accelerate wheel scrolling when events arrive in
/// quick succession. Once one step moves at least a quarter of the viewport,
/// pause this long so the acceleration decays before the next batch; otherwise
/// a step can jump past the whole viewport and leave nothing to align against.
const ACCELERATION_COOLDOWN: Duration = Duration::from_millis(300);
/// Single-event downward steps tried to regain overlap after an overshoot.
const MAX_RECOVER_STEPS: u8 = 12;
/// How long the screen must stay unchanged, while upward batches keep being
/// sent, before it counts as the top. Agents may load or lay out older
/// messages lazily, and a slow redraw must not end the harvest early.
const TOP_CONFIRM: Duration = Duration::from_millis(1500);
/// Upper bound on rows one alternate-screen read may return.
pub(crate) const MAX_HARVEST_LINES: u32 = 100_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    SettleInitial,
    ProbeBottom,
    RestoreProbe,
    Harvest,
    /// Waiting for agent-side wheel acceleration to decay.
    Cooldown,
    /// Stepping back down after a scroll jumped past the previous viewport.
    Recover,
    Restore,
}

pub(crate) struct PendingAltScreenRead {
    pub(crate) terminal_id: TerminalId,
    request_id: String,
    respond_to: mpsc::Sender<String>,
    fallback_response: String,
    read: PaneReadResult,
    lines: usize,
    unwrap: bool,
    initial: ScreenSnapshot,
    previous: ScreenSnapshot,
    history: Vec<crate::ghostty::ScreenTextRow>,
    phase: Phase,
    next_poll_at: Instant,
    step_deadline: Instant,
    output_quiet_until: Option<Instant>,
    step_observed_output: bool,
    synchronized_redraw_pending: bool,
    started_at: Instant,
    restore_started_at: Option<Instant>,
    observed_content_seq: u64,
    upward_events: usize,
    unaligned_grace: u8,
    recover_steps: u8,
    unchanged_since: Option<Instant>,
    reached_top: bool,
    valid: bool,
}

impl PendingAltScreenRead {
    pub(crate) fn start(
        terminal_id: TerminalId,
        request_id: String,
        respond_to: mpsc::Sender<String>,
        fallback_response: String,
        read: PaneReadResult,
        lines: usize,
        unwrap: bool,
        initial: ScreenSnapshot,
        content_seq: u64,
        now: Instant,
    ) -> Self {
        Self {
            terminal_id,
            request_id,
            respond_to,
            fallback_response,
            read,
            lines,
            unwrap,
            previous: initial.clone(),
            history: initial.rows.clone(),
            initial,
            phase: Phase::SettleInitial,
            next_poll_at: now + INITIAL_QUIET,
            step_deadline: now + INITIAL_QUIET,
            output_quiet_until: None,
            step_observed_output: false,
            synchronized_redraw_pending: false,
            started_at: now,
            restore_started_at: None,
            observed_content_seq: content_seq,
            upward_events: 0,
            unaligned_grace: 0,
            recover_steps: 0,
            unchanged_since: None,
            reached_top: false,
            valid: true,
        }
    }

    pub(crate) fn next_deadline(&self) -> Instant {
        self.output_quiet_until.unwrap_or(self.next_poll_at)
    }

    pub(crate) fn frozen_snapshot(
        &self,
        source: crate::api::schema::ReadSource,
        lines: Option<u32>,
    ) -> crate::pane::TerminalReadSnapshot {
        let line_limit = lines.map(|lines| lines.min(MAX_HARVEST_LINES) as usize);
        match source {
            crate::api::schema::ReadSource::Recent
            | crate::api::schema::ReadSource::RecentUnwrapped => {
                let limit = line_limit.unwrap_or(80);
                crate::terminal::snapshot_text(
                    &self.initial.rows,
                    limit,
                    source == crate::api::schema::ReadSource::RecentUnwrapped,
                    self.initial.rows.len() > limit,
                )
            }
            crate::api::schema::ReadSource::Visible | crate::api::schema::ReadSource::Detection => {
                let snapshot = crate::terminal::snapshot_text(
                    &self.initial.rows,
                    self.initial.rows.len(),
                    false,
                    false,
                );
                crate::app::limit_snapshot_lines(snapshot.text, line_limit)
            }
        }
    }

    pub(crate) fn abort(mut self, runtime: Option<&TerminalRuntime>, now: Instant) -> PollOutcome {
        self.valid = false;
        match self.phase {
            Phase::SettleInitial => self.complete_fallback(),
            Phase::Harvest | Phase::Cooldown | Phase::Recover => match runtime {
                Some(runtime) => self.start_restore(runtime, now, None),
                None => self.complete_fallback(),
            },
            Phase::ProbeBottom | Phase::RestoreProbe | Phase::Restore => self.poll(runtime, now),
        }
    }

    pub(crate) fn poll(mut self, runtime: Option<&TerminalRuntime>, now: Instant) -> PollOutcome {
        let Some(runtime) = runtime else {
            return self.complete_fallback();
        };
        let restore_expired = self
            .restore_started_at
            .is_some_and(|started| now.duration_since(started) >= MAX_RESTORE_DURATION);
        if restore_expired {
            // The rows are already harvested; failing to scroll the viewport all
            // the way back must not throw them away.
            return if self.valid && self.phase == Phase::Restore {
                self.complete_success()
            } else {
                self.complete_fallback()
            };
        }
        let traversal_expired = now.duration_since(self.started_at) >= MAX_DURATION
            && matches!(
                self.phase,
                Phase::SettleInitial
                    | Phase::ProbeBottom
                    | Phase::Harvest
                    | Phase::Cooldown
                    | Phase::Recover
            );
        if traversal_expired {
            match self.phase {
                Phase::SettleInitial => {
                    self.valid = false;
                    return self.complete_fallback();
                }
                // Out of time mid-harvest: keep the partial history (reported
                // as truncated because the top was not reached).
                Phase::Harvest | Phase::Cooldown | Phase::Recover => {
                    return self.start_restore(runtime, now, None)
                }
                Phase::ProbeBottom => self.valid = false,
                Phase::RestoreProbe | Phase::Restore => unreachable!(),
            }
        }

        let content_seq = runtime.content_seq();
        if content_seq != self.observed_content_seq {
            self.observed_content_seq = content_seq;
            self.step_observed_output = true;
            let synchronized_frame_complete =
                self.synchronized_redraw_pending && !runtime.synchronized_output_active();
            if synchronized_frame_complete {
                self.synchronized_redraw_pending = false;
                self.output_quiet_until = None;
            } else {
                self.output_quiet_until = Some(now + OUTPUT_QUIET);
                if !traversal_expired {
                    return Some(self);
                }
            }
        }
        if !traversal_expired && self.output_quiet_until.is_some_and(|quiet| now < quiet) {
            return Some(self);
        }
        self.output_quiet_until = None;
        if !traversal_expired && runtime.synchronized_output_active() {
            self.synchronized_redraw_pending = true;
            self.next_poll_at = now + OUTPUT_QUIET;
            return Some(self);
        }
        let step_expired = now >= self.step_deadline;
        let output_observed = self.step_observed_output;
        if !step_expired && !output_observed {
            return Some(self);
        }
        let Some((screen, snapshot, snapshot_seq)) = runtime.screen_text_snapshot_with_seq() else {
            if traversal_expired {
                return self.complete_fallback();
            }
            self.observed_content_seq = runtime.content_seq();
            self.step_observed_output = false;
            self.output_quiet_until = None;
            self.next_poll_at = now + OUTPUT_QUIET;
            return Some(self);
        };
        if runtime.content_seq() != snapshot_seq {
            self.observed_content_seq = snapshot_seq;
            self.step_observed_output = false;
            self.next_poll_at = now + OUTPUT_QUIET;
            return Some(self);
        }
        if screen != crate::ghostty::ActiveScreen::Alternate
            || snapshot.cols != self.initial.cols
            || snapshot.rows.len() != self.initial.rows.len()
        {
            return self.complete_fallback();
        }
        match self.phase {
            Phase::SettleInitial => {
                if output_observed || !snapshot.similar_text(&self.initial) {
                    self.initial = snapshot.clone();
                    self.previous = snapshot.clone();
                    self.history = snapshot.rows;
                    self.observed_content_seq = snapshot_seq;
                    self.step_observed_output = false;
                    self.next_poll_at = now + INITIAL_QUIET;
                    self.step_deadline = self.next_poll_at;
                    return Some(self);
                }
                if send_wheel(
                    runtime,
                    MouseEventKind::ScrollDown,
                    WHEEL_STEP_EVENTS,
                    &snapshot,
                )
                .is_err()
                {
                    return self.complete_fallback();
                }
                self.phase = Phase::ProbeBottom;
                self.arm_step(snapshot_seq, now);
                Some(self)
            }
            Phase::ProbeBottom => {
                let at_bottom = snapshot.similar_text(&self.initial);
                if output_observed && at_bottom && !step_expired && !traversal_expired {
                    self.step_observed_output = false;
                    return Some(self);
                }
                debug!(
                    terminal_id = %self.terminal_id,
                    at_bottom,
                    "alternate-screen read bottom probe settled"
                );
                if at_bottom {
                    if self.valid {
                        self.start_harvest(runtime, now, snapshot_seq)
                    } else {
                        self.complete_fallback()
                    }
                } else {
                    if send_wheel(
                        runtime,
                        MouseEventKind::ScrollUp,
                        WHEEL_STEP_EVENTS,
                        &snapshot,
                    )
                    .is_err()
                    {
                        return self.complete_fallback();
                    }
                    self.phase = Phase::RestoreProbe;
                    self.restore_started_at = Some(now);
                    self.arm_step(snapshot_seq, now);
                    Some(self)
                }
            }
            Phase::RestoreProbe => {
                if snapshot.similar_text(&self.initial) {
                    self.complete_fallback()
                } else {
                    self.step_observed_output = false;
                    if step_expired {
                        self.next_poll_at = now + STEP_TIMEOUT;
                        self.step_deadline = self.next_poll_at;
                    }
                    Some(self)
                }
            }
            Phase::Harvest | Phase::Cooldown | Phase::Recover => {
                let merge = crate::terminal::merge_scrolled_up(
                    &mut self.history,
                    &self.previous,
                    &snapshot,
                );
                debug!(
                    terminal_id = %self.terminal_id,
                    phase = ?self.phase,
                    ?merge,
                    retained_rows = self.history.len(),
                    batch_events = WHEEL_STEP_EVENTS,
                    step_expired,
                    "alternate-screen harvest snapshot"
                );
                if merge == UpwardMerge::Unaligned && step_expired {
                    debug!(
                        terminal_id = %self.terminal_id,
                        previous = ?self.previous.debug_identities(),
                        next = ?snapshot.debug_identities(),
                        "alternate-screen harvest unaligned frames"
                    );
                }
                match (self.phase, merge) {
                    (_, UpwardMerge::Advanced { rows }) => {
                        self.unaligned_grace = 0;
                        self.recover_steps = 0;
                        self.unchanged_since = None;
                        self.previous = snapshot;
                        if self.history.len() >= self.lines {
                            self.start_restore(runtime, now, Some(snapshot_seq))
                        } else if rows >= cooldown_rows(&self.previous) {
                            self.start_cooldown(now, snapshot_seq)
                        } else {
                            self.start_harvest(runtime, now, snapshot_seq)
                        }
                    }
                    (_, UpwardMerge::Unchanged | UpwardMerge::Unaligned) if !step_expired => {
                        self.step_observed_output = false;
                        Some(self)
                    }
                    (Phase::Cooldown | Phase::Recover, UpwardMerge::Unchanged) => {
                        self.start_harvest(runtime, now, snapshot_seq)
                    }
                    (_, UpwardMerge::Unchanged) => {
                        let since = *self.unchanged_since.get_or_insert(now);
                        if now.duration_since(since) < TOP_CONFIRM {
                            self.start_harvest(runtime, now, snapshot_seq)
                        } else {
                            self.reached_top = true;
                            self.start_restore(runtime, now, Some(snapshot_seq))
                        }
                    }
                    (_, UpwardMerge::Unaligned)
                        if crate::terminal::scrolled_down(&self.previous, &snapshot) =>
                    {
                        // The agent moved its viewport down a little. Nothing new
                        // to keep, but continue from this frame.
                        self.unaligned_grace = 0;
                        self.previous = snapshot;
                        self.start_harvest(runtime, now, snapshot_seq)
                    }
                    (Phase::Harvest, UpwardMerge::Unaligned)
                        if self.unaligned_grace < UNALIGNED_GRACE_STEPS =>
                    {
                        // A slow redraw can still be in flight; give it more time.
                        self.unaligned_grace += 1;
                        self.step_observed_output = false;
                        self.next_poll_at = now + STEP_TIMEOUT;
                        self.step_deadline = self.next_poll_at;
                        Some(self)
                    }
                    (_, UpwardMerge::Unaligned) if self.recover_steps < MAX_RECOVER_STEPS => {
                        self.start_recover(runtime, now, snapshot_seq)
                    }
                    (_, UpwardMerge::Unaligned) => {
                        // Give up but keep everything merged so far; the response
                        // is marked truncated because the top was not reached.
                        self.start_restore(runtime, now, Some(snapshot_seq))
                    }
                }
            }
            Phase::Restore => {
                if snapshot.similar_text(&self.initial) {
                    if self.valid {
                        self.complete_success()
                    } else {
                        self.complete_fallback()
                    }
                } else if step_expired || !snapshot.similar_text(&self.previous) {
                    if send_wheel(
                        runtime,
                        MouseEventKind::ScrollDown,
                        restore_batch_size(&snapshot),
                        &snapshot,
                    )
                    .is_err()
                    {
                        return self.complete_fallback();
                    }
                    self.previous = snapshot;
                    self.arm_step(snapshot_seq, now);
                    Some(self)
                } else {
                    self.step_observed_output = false;
                    Some(self)
                }
            }
        }
    }

    fn start_harvest(
        mut self,
        runtime: &TerminalRuntime,
        now: Instant,
        baseline_seq: u64,
    ) -> PollOutcome {
        let events = WHEEL_STEP_EVENTS;
        if send_wheel(runtime, MouseEventKind::ScrollUp, events, &self.previous).is_err() {
            return self.complete_fallback();
        }
        self.upward_events = self.upward_events.saturating_add(events);
        self.phase = Phase::Harvest;
        self.arm_step(baseline_seq, now);
        Some(self)
    }

    fn start_cooldown(mut self, now: Instant, baseline_seq: u64) -> PollOutcome {
        self.phase = Phase::Cooldown;
        self.arm_step(baseline_seq, now);
        self.next_poll_at = now + ACCELERATION_COOLDOWN;
        self.step_deadline = self.next_poll_at;
        Some(self)
    }

    fn start_recover(
        mut self,
        runtime: &TerminalRuntime,
        now: Instant,
        baseline_seq: u64,
    ) -> PollOutcome {
        if send_wheel(runtime, MouseEventKind::ScrollDown, 1, &self.previous).is_err() {
            return self.start_restore(runtime, now, Some(baseline_seq));
        }
        self.recover_steps += 1;
        self.unaligned_grace = 0;
        self.phase = Phase::Recover;
        self.arm_step(baseline_seq, now);
        Some(self)
    }

    fn start_restore(
        mut self,
        runtime: &TerminalRuntime,
        now: Instant,
        baseline_seq: Option<u64>,
    ) -> PollOutcome {
        if self.upward_events == 0 {
            return self.complete_fallback();
        }
        let baseline_seq = baseline_seq.unwrap_or_else(|| runtime.content_seq());
        if send_wheel(
            runtime,
            MouseEventKind::ScrollDown,
            self.upward_events,
            &self.previous,
        )
        .is_err()
        {
            return self.complete_fallback();
        }
        self.phase = Phase::Restore;
        self.restore_started_at = Some(now);
        self.arm_step(baseline_seq, now);
        Some(self)
    }

    fn arm_step(&mut self, baseline_seq: u64, now: Instant) {
        self.observed_content_seq = baseline_seq;
        self.output_quiet_until = None;
        self.step_observed_output = false;
        self.synchronized_redraw_pending = false;
        self.next_poll_at = now + STEP_TIMEOUT;
        self.step_deadline = self.next_poll_at;
    }

    fn complete_success(mut self) -> PollOutcome {
        debug!(
            terminal_id = %self.terminal_id,
            retained_rows = self.history.len(),
            requested_rows = self.lines,
            reached_top = self.reached_top,
            "alternate-screen read completed"
        );
        let truncated = !self.reached_top || self.history.len() > self.lines;
        let snapshot =
            crate::terminal::snapshot_text(&self.history, self.lines, self.unwrap, truncated);
        self.read.text = snapshot.text;
        self.read.truncated = snapshot.truncated;
        let response = serde_json::to_string(&SuccessResponse {
            id: self.request_id,
            result: ResponseResult::PaneRead { read: self.read },
        })
        .unwrap_or(self.fallback_response);
        let _ = self.respond_to.send(response);
        None
    }

    fn complete_fallback(self) -> PollOutcome {
        debug!(
            terminal_id = %self.terminal_id,
            ?self.phase,
            retained_rows = self.history.len(),
            upward_events = self.upward_events,
            valid = self.valid,
            "alternate-screen read fell back to passive snapshot"
        );
        let _ = self.respond_to.send(self.fallback_response);
        None
    }
}

pub(crate) type PollOutcome = Option<PendingAltScreenRead>;

fn cooldown_rows(snapshot: &ScreenSnapshot) -> usize {
    snapshot.rows.len().saturating_div(4).max(4)
}

fn restore_batch_size(snapshot: &ScreenSnapshot) -> usize {
    snapshot.rows.len().saturating_div(2).max(1)
}

fn send_wheel(
    runtime: &TerminalRuntime,
    kind: MouseEventKind,
    events: usize,
    snapshot: &ScreenSnapshot,
) -> Result<(), ()> {
    if runtime.wheel_routing() != Some(crate::pane::WheelRouting::MouseReport) {
        return Err(());
    }
    let column = snapshot.cols.saturating_sub(1) / 2;
    let row = u16::try_from(snapshot.rows.len().saturating_sub(1) / 2).unwrap_or(0);
    let event = runtime
        .encode_mouse_wheel(
            kind,
            crate::input::mouse::Position::Cell { column, row },
            KeyModifiers::empty(),
        )
        .ok_or(())?;
    let mut bytes = Vec::with_capacity(event.len().saturating_mul(events));
    for _ in 0..events {
        bytes.extend_from_slice(&event);
    }
    runtime.try_send_bytes(Bytes::from(bytes)).map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::schema::{ReadFormat, ReadSource};

    fn draw(lines: &[&str], enter_alt_screen: bool) -> Vec<u8> {
        let mut bytes = Vec::new();
        if enter_alt_screen {
            bytes.extend_from_slice(b"\x1b[?1049h\x1b[?1000h\x1b[?1006h");
        }
        bytes.extend_from_slice(b"\x1b[2J\x1b[H");
        bytes.extend_from_slice(lines.join("\r\n").as_bytes());
        bytes
    }

    fn pending_read(
        runtime: &TerminalRuntime,
        now: Instant,
        lines: usize,
    ) -> (PendingAltScreenRead, mpsc::Receiver<String>) {
        let (_, initial) = runtime.screen_text_snapshot().expect("initial snapshot");
        let (respond_to, response_rx) = mpsc::channel();
        let pending = PendingAltScreenRead::start(
            TerminalId::alloc(),
            "read".into(),
            respond_to,
            "fallback".into(),
            PaneReadResult {
                pane_id: "w1:p1".into(),
                workspace_id: "w1".into(),
                tab_id: "w1:t1".into(),
                source: ReadSource::Recent,
                format: ReadFormat::Text,
                text: String::new(),
                revision: 0,
                truncated: false,
            },
            lines,
            false,
            initial,
            runtime.content_seq(),
            now,
        );
        (pending, response_rx)
    }

    fn response_read(response_rx: &mpsc::Receiver<String>) -> PaneReadResult {
        let response: SuccessResponse = serde_json::from_str(
            &response_rx
                .recv_timeout(Duration::from_millis(50))
                .expect("read response"),
        )
        .expect("valid response");
        let ResponseResult::PaneRead { read } = response.result else {
            panic!("expected pane read response");
        };
        read
    }

    /// Draws `lines`, lets the redraw settle, and returns the pending read after
    /// it reacted to the frame.
    fn show(
        pending: PendingAltScreenRead,
        runtime: &TerminalRuntime,
        input_rx: &mut tokio::sync::mpsc::Receiver<Bytes>,
        now: &mut Instant,
        lines: &[&str],
    ) -> PollOutcome {
        runtime.test_process_pty_bytes(&draw(lines, false));
        *now += Duration::from_millis(1);
        let pending = pending.poll(Some(runtime), *now)?;
        *now += OUTPUT_QUIET + Duration::from_millis(1);
        let pending = pending.poll(Some(runtime), *now);
        while input_rx.try_recv().is_ok() {}
        pending
    }

    /// Keeps polling without new output until the read reaches `phase`.
    fn idle_until(
        mut pending: PendingAltScreenRead,
        runtime: &TerminalRuntime,
        input_rx: &mut tokio::sync::mpsc::Receiver<Bytes>,
        now: &mut Instant,
        phase: Phase,
    ) -> PendingAltScreenRead {
        for _ in 0..200 {
            if pending.phase == phase {
                return pending;
            }
            *now += STEP_TIMEOUT;
            pending = pending
                .poll(Some(runtime), *now)
                .expect("read should still be pending");
            while input_rx.try_recv().is_ok() {}
        }
        panic!("read never reached {phase:?}");
    }

    fn response_text(response_rx: &mpsc::Receiver<String>) -> String {
        let response: SuccessResponse = serde_json::from_str(
            &response_rx
                .recv_timeout(Duration::from_millis(50))
                .expect("read response"),
        )
        .expect("valid response");
        let ResponseResult::PaneRead { read } = response.result else {
            panic!("expected pane read response");
        };
        read.text
    }

    #[test]
    fn hard_deadline_wins_over_continuous_output_coalescing() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime");
        let _guard = rt.enter();
        let (runtime, _input_rx) = TerminalRuntime::test_with_channel_capacity(20, 5, 8);
        runtime.test_process_pty_bytes(&draw(&["16", "17", "18", "19", "20"], true));
        let started = Instant::now();
        let (pending, response_rx) = pending_read(&runtime, started, 8);

        runtime.test_process_pty_bytes(b"\x1b]0;still changing\x07");
        assert!(pending
            .poll(Some(&runtime), started + MAX_DURATION)
            .is_none());
        assert_eq!(
            response_rx
                .recv_timeout(Duration::from_millis(50))
                .expect("fallback response"),
            "fallback"
        );

        drop(runtime);
        drop(_guard);
        rt.shutdown_timeout(Duration::from_millis(100));
    }

    #[test]
    fn probe_bottom_hard_deadline_wins_over_continuous_output() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime");
        let _guard = rt.enter();
        let (runtime, mut input_rx) = TerminalRuntime::test_with_channel_capacity(20, 5, 8);
        runtime.test_process_pty_bytes(&draw(&["16", "17", "18", "19", "20"], true));
        let started = Instant::now();
        let (pending, response_rx) = pending_read(&runtime, started, 8);
        let pending = pending
            .poll(Some(&runtime), started + INITIAL_QUIET)
            .expect("bottom probe");
        input_rx.try_recv().expect("bottom wheel probe");

        runtime.test_process_pty_bytes(b"\x1b]0;still changing\x07");
        assert!(pending
            .poll(Some(&runtime), started + MAX_DURATION)
            .is_none());
        assert_eq!(
            response_rx
                .recv_timeout(Duration::from_millis(50))
                .expect("fallback response"),
            "fallback"
        );

        drop(runtime);
        drop(_guard);
        rt.shutdown_timeout(Duration::from_millis(100));
    }

    #[test]
    fn probe_bottom_hard_deadline_wins_over_synchronized_output() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime");
        let _guard = rt.enter();
        let (runtime, mut input_rx) = TerminalRuntime::test_with_channel_capacity(20, 5, 8);
        runtime.test_process_pty_bytes(&draw(&["16", "17", "18", "19", "20"], true));
        let started = Instant::now();
        let (pending, response_rx) = pending_read(&runtime, started, 8);
        let pending = pending
            .poll(Some(&runtime), started + INITIAL_QUIET)
            .expect("bottom probe");
        input_rx.try_recv().expect("bottom wheel probe");

        runtime.test_process_pty_bytes(b"\x1b[?2026h");
        assert!(pending
            .poll(Some(&runtime), started + MAX_DURATION)
            .is_none());
        assert_eq!(
            response_rx
                .recv_timeout(Duration::from_millis(50))
                .expect("fallback response"),
            "fallback"
        );

        drop(runtime);
        drop(_guard);
        rt.shutdown_timeout(Duration::from_millis(100));
    }

    #[test]
    fn redraw_events_advance_harvest_and_restore_without_settle_delays() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime");
        let _guard = rt.enter();
        let initial_bytes = draw(&["16", "17", "18", "19", "20"], true);
        let (runtime, mut input_rx) = TerminalRuntime::test_with_channel_capacity(20, 5, 8);
        runtime.test_process_pty_bytes(&initial_bytes);
        let started = Instant::now();
        let (pending, response_rx) = pending_read(&runtime, started, 8);

        let pending = pending
            .poll(Some(&runtime), started + INITIAL_QUIET)
            .expect("bottom probe");
        input_rx.try_recv().expect("bottom wheel probe");
        let pending = pending
            .poll(Some(&runtime), started + INITIAL_QUIET + STEP_TIMEOUT)
            .expect("history harvest");
        input_rx.try_recv().expect("upward wheel batch");

        runtime.test_process_pty_bytes(&draw(&["13", "14", "15", "16", "17"], false));
        let pending = pending
            .poll(
                Some(&runtime),
                started + INITIAL_QUIET + STEP_TIMEOUT + Duration::from_millis(1),
            )
            .expect("redraw coalescing");
        assert!(input_rx.try_recv().is_err());
        let pending = pending
            .poll(
                Some(&runtime),
                started + INITIAL_QUIET + STEP_TIMEOUT + Duration::from_millis(11),
            )
            .expect("viewport restore");
        input_rx.try_recv().expect("restore wheel batch");

        runtime.test_process_pty_bytes(&draw(&["16", "17", "18", "19", "20"], false));
        let pending = pending
            .poll(
                Some(&runtime),
                started + INITIAL_QUIET + STEP_TIMEOUT + Duration::from_millis(12),
            )
            .expect("restore redraw coalescing");
        assert!(
            pending
                .poll(
                    Some(&runtime),
                    started + INITIAL_QUIET + STEP_TIMEOUT + Duration::from_millis(22),
                )
                .is_none(),
            "restored redraw should complete after coalescing"
        );
        assert_eq!(
            response_text(&response_rx),
            "13\n14\n15\n16\n17\n18\n19\n20\n"
        );

        drop(runtime);
        drop(_guard);
        rt.shutdown_timeout(Duration::from_millis(100));
    }

    #[test]
    fn restore_keeps_trying_after_a_slow_redraw_exceeds_the_step_timeout() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime");
        let _guard = rt.enter();
        let (runtime, mut input_rx) = TerminalRuntime::test_with_channel_capacity(20, 5, 8);
        runtime.test_process_pty_bytes(&draw(&["16", "17", "18", "19", "20"], true));
        let started = Instant::now();
        let (pending, response_rx) = pending_read(&runtime, started, 8);
        let harvest_started = started + INITIAL_QUIET + STEP_TIMEOUT;

        let pending = pending
            .poll(Some(&runtime), started + INITIAL_QUIET)
            .expect("bottom probe");
        input_rx.try_recv().expect("bottom wheel probe");
        let pending = pending
            .poll(Some(&runtime), harvest_started)
            .expect("history harvest");
        input_rx.try_recv().expect("upward wheel batch");
        runtime.test_process_pty_bytes(&draw(&["13", "14", "15", "16", "17"], false));
        let pending = pending
            .poll(Some(&runtime), harvest_started + Duration::from_millis(1))
            .expect("redraw coalescing");
        let restore_started = harvest_started + Duration::from_millis(11);
        let pending = pending
            .poll(Some(&runtime), restore_started)
            .expect("viewport restore");
        input_rx.try_recv().expect("restore wheel batch");

        let retry_at = restore_started + STEP_TIMEOUT;
        let pending = pending
            .poll(Some(&runtime), retry_at)
            .expect("slow restore must remain pending");
        input_rx.try_recv().expect("retry restore wheel batch");

        runtime.test_process_pty_bytes(&draw(&["16", "17", "18", "19", "20"], false));
        let pending = pending
            .poll(Some(&runtime), retry_at + Duration::from_millis(1))
            .expect("restore redraw coalescing");
        assert!(pending
            .poll(Some(&runtime), retry_at + Duration::from_millis(11))
            .is_none());
        assert_eq!(
            response_text(&response_rx),
            "13\n14\n15\n16\n17\n18\n19\n20\n"
        );

        drop(runtime);
        drop(_guard);
        rt.shutdown_timeout(Duration::from_millis(100));
    }

    #[test]
    fn unrelated_output_does_not_retry_restore_before_the_step_timeout() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime");
        let _guard = rt.enter();
        let initial = ["16", "17", "18", "19", "20"];
        let (runtime, mut input_rx) = TerminalRuntime::test_with_channel_capacity(20, 5, 8);
        runtime.test_process_pty_bytes(&draw(&initial, true));
        let started = Instant::now();
        let (pending, response_rx) = pending_read(&runtime, started, 8);
        let harvest_started = started + INITIAL_QUIET + STEP_TIMEOUT;

        let pending = pending
            .poll(Some(&runtime), started + INITIAL_QUIET)
            .expect("bottom probe");
        input_rx.try_recv().expect("bottom wheel probe");
        let pending = pending
            .poll(Some(&runtime), harvest_started)
            .expect("history harvest");
        input_rx.try_recv().expect("upward wheel batch");
        runtime.test_process_pty_bytes(&draw(&["13", "14", "15", "16", "17"], false));
        let pending = pending
            .poll(Some(&runtime), harvest_started + Duration::from_millis(1))
            .expect("redraw coalescing");
        let restore_started = harvest_started + Duration::from_millis(11);
        let pending = pending
            .poll(Some(&runtime), restore_started)
            .expect("viewport restore");
        input_rx.try_recv().expect("restore wheel batch");

        runtime.test_process_pty_bytes(b"\x1b]0;unrelated title\x07");
        let pending = pending
            .poll(Some(&runtime), restore_started + Duration::from_millis(1))
            .expect("unrelated output coalescing");
        let pending = pending
            .poll(Some(&runtime), restore_started + Duration::from_millis(11))
            .expect("restore remains pending");
        assert!(input_rx.try_recv().is_err());

        runtime.test_process_pty_bytes(&draw(&initial, false));
        let pending = pending
            .poll(Some(&runtime), restore_started + Duration::from_millis(12))
            .expect("restore redraw coalescing");
        assert!(pending
            .poll(Some(&runtime), restore_started + Duration::from_millis(22))
            .is_none());
        assert_eq!(
            response_text(&response_rx),
            "13\n14\n15\n16\n17\n18\n19\n20\n"
        );

        drop(runtime);
        drop(_guard);
        rt.shutdown_timeout(Duration::from_millis(100));
    }

    #[test]
    fn synchronized_redraw_is_not_consumed_after_the_step_timeout() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime");
        let _guard = rt.enter();
        let initial = ["16", "17", "18", "19", "20"];
        let (runtime, mut input_rx) = TerminalRuntime::test_with_channel_capacity(20, 5, 8);
        runtime.test_process_pty_bytes(&draw(&initial, true));
        let started = Instant::now();
        let (pending, response_rx) = pending_read(&runtime, started, 8);
        let harvest_started = started + INITIAL_QUIET + STEP_TIMEOUT;

        let pending = pending
            .poll(Some(&runtime), started + INITIAL_QUIET)
            .expect("bottom probe");
        input_rx.try_recv().expect("bottom wheel probe");
        let pending = pending
            .poll(Some(&runtime), harvest_started)
            .expect("history harvest");
        input_rx.try_recv().expect("upward wheel batch");

        let mut synchronized = b"\x1b[?2026h".to_vec();
        synchronized.extend(draw(&["13", "14", "15", "16", "17"], false));
        runtime.test_process_pty_bytes(&synchronized);
        let pending = pending
            .poll(Some(&runtime), harvest_started + Duration::from_millis(1))
            .expect("synchronized redraw observed");
        let pending = pending
            .poll(
                Some(&runtime),
                harvest_started + STEP_TIMEOUT + Duration::from_millis(1),
            )
            .expect("synchronized redraw must remain pending");
        assert!(input_rx.try_recv().is_err());

        runtime.test_process_pty_bytes(b"\x1b[?2026l");
        let pending = pending
            .poll(
                Some(&runtime),
                harvest_started + STEP_TIMEOUT + Duration::from_millis(2),
            )
            .expect("viewport restore after synchronized redraw");
        input_rx.try_recv().expect("restore wheel batch");

        runtime.test_process_pty_bytes(&draw(&initial, false));
        let pending = pending
            .poll(
                Some(&runtime),
                harvest_started + STEP_TIMEOUT + Duration::from_millis(3),
            )
            .expect("restore redraw coalescing");
        assert!(pending
            .poll(
                Some(&runtime),
                harvest_started + STEP_TIMEOUT + Duration::from_millis(13)
            )
            .is_none());
        assert_eq!(
            response_text(&response_rx),
            "13\n14\n15\n16\n17\n18\n19\n20\n"
        );

        drop(runtime);
        drop(_guard);
        rt.shutdown_timeout(Duration::from_millis(100));
    }

    #[test]
    fn aligned_intermediate_redraw_is_coalesced_before_scrolling_again() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime");
        let _guard = rt.enter();
        let initial = ["16", "17", "18", "19", "20", "ready"];
        let (runtime, mut input_rx) = TerminalRuntime::test_with_channel_capacity(20, 6, 8);
        runtime.test_process_pty_bytes(&draw(&initial, true));
        let started = Instant::now();
        let (pending, response_rx) = pending_read(&runtime, started, 9);
        let harvest_started = started + INITIAL_QUIET + STEP_TIMEOUT;

        let pending = pending
            .poll(Some(&runtime), started + INITIAL_QUIET)
            .expect("bottom probe");
        input_rx.try_recv().expect("bottom wheel probe");
        let pending = pending
            .poll(Some(&runtime), harvest_started)
            .expect("history harvest");
        input_rx.try_recv().expect("upward wheel batch");

        runtime.test_process_pty_bytes(&draw(&["13", "14", "15", "16", "17", "loading"], false));
        let pending = pending
            .poll(Some(&runtime), harvest_started + Duration::from_millis(1))
            .expect("intermediate redraw coalescing");
        assert!(input_rx.try_recv().is_err());
        runtime.test_process_pty_bytes(&draw(&["13", "14", "15", "16", "17", "ready"], false));
        let pending = pending
            .poll(Some(&runtime), harvest_started + Duration::from_millis(5))
            .expect("completed redraw coalescing");
        assert!(input_rx.try_recv().is_err());
        let pending = pending
            .poll(Some(&runtime), harvest_started + Duration::from_millis(15))
            .expect("viewport restore after completed redraw");
        input_rx.try_recv().expect("restore wheel batch");

        runtime.test_process_pty_bytes(&draw(&initial, false));
        let pending = pending
            .poll(Some(&runtime), harvest_started + Duration::from_millis(16))
            .expect("restore redraw coalescing");
        assert!(pending
            .poll(Some(&runtime), harvest_started + Duration::from_millis(26))
            .is_none());
        assert_eq!(
            response_text(&response_rx),
            "13\n14\n15\n16\n17\n18\n19\n20\nready\n"
        );

        drop(runtime);
        drop(_guard);
        rt.shutdown_timeout(Duration::from_millis(100));
    }

    #[test]
    fn incomplete_redraw_waits_for_an_aligned_screen_without_resetting_timeout() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime");
        let _guard = rt.enter();
        let initial_bytes = draw(&["16", "17", "18", "19", "20"], true);
        let (runtime, mut input_rx) = TerminalRuntime::test_with_channel_capacity(20, 5, 8);
        runtime.test_process_pty_bytes(&initial_bytes);
        let started = Instant::now();
        let (pending, response_rx) = pending_read(&runtime, started, 8);

        let pending = pending
            .poll(Some(&runtime), started + INITIAL_QUIET)
            .expect("bottom probe");
        input_rx.try_recv().expect("bottom wheel probe");
        let pending = pending
            .poll(Some(&runtime), started + INITIAL_QUIET + STEP_TIMEOUT)
            .expect("history harvest");
        input_rx.try_recv().expect("upward wheel batch");

        runtime.test_process_pty_bytes(&draw(&["13"], false));
        let pending = pending
            .poll(
                Some(&runtime),
                started + INITIAL_QUIET + STEP_TIMEOUT + Duration::from_millis(1),
            )
            .expect("partial redraw coalescing");
        let pending = pending
            .poll(
                Some(&runtime),
                started + INITIAL_QUIET + STEP_TIMEOUT + Duration::from_millis(11),
            )
            .expect("partial redraw must not complete");
        assert!(
            input_rx.try_recv().is_err(),
            "partial redraw must not scroll again"
        );

        runtime.test_process_pty_bytes(&draw(&["13", "14", "15", "16", "17"], false));
        let pending = pending
            .poll(
                Some(&runtime),
                started + INITIAL_QUIET + STEP_TIMEOUT + Duration::from_millis(12),
            )
            .expect("aligned redraw coalescing");
        let pending = pending
            .poll(
                Some(&runtime),
                started + INITIAL_QUIET + STEP_TIMEOUT + Duration::from_millis(22),
            )
            .expect("aligned redraw should start restore");
        input_rx.try_recv().expect("restore wheel batch");
        runtime.test_process_pty_bytes(&draw(&["16", "17", "18", "19", "20"], false));
        let pending = pending
            .poll(
                Some(&runtime),
                started + INITIAL_QUIET + STEP_TIMEOUT + Duration::from_millis(23),
            )
            .expect("restore redraw coalescing");
        assert!(pending
            .poll(
                Some(&runtime),
                started + INITIAL_QUIET + STEP_TIMEOUT + Duration::from_millis(33),
            )
            .is_none());
        assert_eq!(
            response_text(&response_rx),
            "13\n14\n15\n16\n17\n18\n19\n20\n"
        );

        drop(runtime);
        drop(_guard);
        rt.shutdown_timeout(Duration::from_millis(100));
    }
    #[test]
    fn unalignable_frame_keeps_the_partial_history() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime");
        let _guard = rt.enter();
        let initial = ["16", "17", "18", "19", "20"];
        let (runtime, mut input_rx) = TerminalRuntime::test_with_channel_capacity(20, 5, 8);
        runtime.test_process_pty_bytes(&draw(&initial, true));
        let mut now = Instant::now();
        let (pending, response_rx) = pending_read(&runtime, now, 100);

        now += INITIAL_QUIET;
        let pending = pending.poll(Some(&runtime), now).expect("bottom probe");
        now += STEP_TIMEOUT;
        let pending = pending.poll(Some(&runtime), now).expect("history harvest");
        while input_rx.try_recv().is_ok() {}

        let pending = show(
            pending,
            &runtime,
            &mut input_rx,
            &mut now,
            &["13", "14", "15", "16", "17"],
        )
        .expect("aligned step keeps harvesting");
        // The next frame shares nothing with the previous one, as when an
        // accelerated scroll jumps past the whole viewport.
        let pending = show(
            pending,
            &runtime,
            &mut input_rx,
            &mut now,
            &["a", "b", "c", "d", "e"],
        )
        .expect("unaligned frame waits");
        let pending = idle_until(pending, &runtime, &mut input_rx, &mut now, Phase::Restore);
        assert!(!pending.reached_top);

        assert!(show(pending, &runtime, &mut input_rx, &mut now, &initial).is_none());
        let read = response_read(&response_rx);
        assert_eq!(read.text, "13\n14\n15\n16\n17\n18\n19\n20\n");
        assert!(
            read.truncated,
            "a partial harvest must be reported as truncated"
        );

        drop(runtime);
        drop(_guard);
        rt.shutdown_timeout(Duration::from_millis(100));
    }

    #[test]
    fn downward_nudge_continues_from_the_new_frame_and_top_needs_confirmation() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime");
        let _guard = rt.enter();
        let initial = ["16", "17", "18", "19", "20"];
        let (runtime, mut input_rx) = TerminalRuntime::test_with_channel_capacity(20, 5, 8);
        runtime.test_process_pty_bytes(&draw(&initial, true));
        let mut now = Instant::now();
        let (pending, response_rx) = pending_read(&runtime, now, 100);

        now += INITIAL_QUIET;
        let pending = pending.poll(Some(&runtime), now).expect("bottom probe");
        now += STEP_TIMEOUT;
        let pending = pending.poll(Some(&runtime), now).expect("history harvest");
        while input_rx.try_recv().is_ok() {}

        let pending = show(
            pending,
            &runtime,
            &mut input_rx,
            &mut now,
            &["13", "14", "15", "16", "17"],
        )
        .expect("aligned step");
        let pending = show(
            pending,
            &runtime,
            &mut input_rx,
            &mut now,
            &["14", "15", "16", "17", "18"],
        )
        .expect("downward nudge waits for its step");
        now += STEP_TIMEOUT;
        let pending = pending.poll(Some(&runtime), now).expect("nudge accepted");
        assert_eq!(pending.phase, Phase::Harvest);
        let pending = show(
            pending,
            &runtime,
            &mut input_rx,
            &mut now,
            &["11", "12", "13", "14", "15"],
        )
        .expect("aligned step after the nudge");

        // An unchanged screen only counts as the top after TOP_CONFIRM.
        let confirm_started = now;
        let pending = idle_until(pending, &runtime, &mut input_rx, &mut now, Phase::Restore);
        assert!(now.duration_since(confirm_started) >= TOP_CONFIRM);
        assert!(pending.reached_top);

        assert!(show(pending, &runtime, &mut input_rx, &mut now, &initial).is_none());
        let read = response_read(&response_rx);
        assert_eq!(read.text, "11\n12\n13\n14\n15\n16\n17\n18\n19\n20\n");
        assert!(!read.truncated);

        drop(runtime);
        drop(_guard);
        rt.shutdown_timeout(Duration::from_millis(100));
    }
}
