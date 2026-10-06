//! The starvation model: two executors, the lower one running tasks that may spin, the higher one preempting it. A task that spins must not stop the console from
//! answering, and the supervisor must name the task that stopped.

use tdongle_boot_guard::watch::{Verdict, Watch};

/// A tick-level model of the board: each tick the high-priority executor runs (it always preempts), then the low one runs its current task.
#[derive(Default)]
struct Board {
    thread_hb: u32,
    console_hb: u32,
    console_answers: u32,
    /// the low executor is stuck in a task that never awaits
    thread_spinning: bool,
    /// the console task itself is stuck (a handler that never returns)
    console_spinning: bool,
    /// interrupts are off (a critical section that never ends): nothing runs, not even the high-priority executor
    interrupts_off: bool,
}

impl Board {
    fn tick(&mut self, console_request: bool) {
        if self.interrupts_off {
            return;
        }
        // high priority executor: the console, the console heartbeat, the supervisor
        if !self.console_spinning {
            self.console_hb += 1;
            if console_request {
                self.console_answers += 1;
            }
        }
        // low priority executor
        if !self.thread_spinning {
            self.thread_hb += 1;
        }
    }
}

fn run(board: &mut Board, ms: u64, watch: &mut Watch<2>, mut hooks: impl FnMut(u64, &mut Board)) -> (u64, Option<&'static str>, u32) {
    let mut fed = 0;
    for now in 0..ms {
        hooks(now, board);
        board.tick(now % 10 == 0);
        if now % 500 == 0 && !board.interrupts_off {
            // the supervisor runs in the high-priority executor: with interrupts off it does not run at all
            match watch.check(now, [board.thread_hb, board.console_hb]) {
                Verdict::Healthy => fed += 1,
                Verdict::Stalled(name) => return (now, Some(name), fed),
            }
        }
    }
    (ms, None, fed)
}

#[test]
fn a_spinning_bridge_task_does_not_stop_the_console_and_is_named() {
    let mut board = Board::default();
    let mut watch = Watch::new(["thread", "console"], [8_000, 3_000], 0);
    let mut answers_before = 0;
    let (t, culprit, fed) = run(&mut board, 60_000, &mut watch, |now, b| {
        if now == 5_000 {
            answers_before = b.console_answers;
            b.thread_spinning = true; // a bridge task starts spinning
        }
    });
    assert_eq!(culprit, Some("thread"));
    assert!((13_000..=14_000).contains(&t), "named within one check of the deadline, got {t}");
    assert!(fed > 0);
    assert!(board.console_answers > answers_before + 500, "the console kept answering the whole time the bridge spun");
}

#[test]
fn a_stuck_console_is_named_console() {
    let mut board = Board::default();
    let mut watch = Watch::new(["thread", "console"], [8_000, 3_000], 0);
    let (_, culprit, _) = run(&mut board, 30_000, &mut watch, |now, b| b.console_spinning |= now == 2_000);
    assert_eq!(culprit, Some("console"));
}

#[test]
fn a_healthy_board_feeds_every_check_and_never_resets() {
    let mut board = Board::default();
    let mut watch = Watch::new(["thread", "console"], [8_000, 3_000], 0);
    let (_, culprit, fed) = run(&mut board, 120_000, &mut watch, |_, _| {});
    assert_eq!(culprit, None);
    assert_eq!(fed, 240);
}

#[test]
fn with_interrupts_off_nothing_runs_so_nothing_is_fed_and_only_the_hardware_watchdog_is_left() {
    let mut board = Board::default();
    let mut watch = Watch::new(["thread", "console"], [8_000, 3_000], 0);
    let (_, culprit, fed) = run(&mut board, 20_000, &mut watch, |now, b| b.interrupts_off |= now == 1_000);
    assert_eq!(culprit, None, "no supervisor runs, so there is no verdict");
    assert!(fed <= 2, "and nothing is fed after the stall: the hardware watchdog (10 s) resets the chip; the `op` tag in RTC names what was running");
}

#[test]
fn counters_may_wrap() {
    let mut watch = Watch::new(["a"], [1_000], 0);
    assert_eq!(watch.check(500, [u32::MAX]), Verdict::Healthy);
    assert_eq!(watch.check(1_000, [0]), Verdict::Healthy, "u32::MAX -> 0 is an advance");
    assert_eq!(watch.check(1_900, [0]), Verdict::Healthy, "within the deadline");
    assert_eq!(watch.check(2_100, [0]), Verdict::Stalled("a"));
}

#[test]
fn nothing_is_stalled_before_its_deadline_at_start_up() {
    let mut watch = Watch::new(["a", "b"], [5_000, 5_000], 0);
    assert_eq!(watch.check(4_000, [0, 0]), Verdict::Healthy);
    assert_eq!(watch.check(5_001, [0, 0]), Verdict::Stalled("a"));
}
