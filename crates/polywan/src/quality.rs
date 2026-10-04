//! Quality gates of a path (SPEC.md FR-PROBE-5): the samples of the last
//! `quality_window` rounds, their loss ratio, median RTT and jitter, and the
//! gates they violate. Pure; the State task owns one [`Window`] per path.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::time::Duration;

use crate::config::{Quality, Target};
use crate::probe::Sample;

/// Replied samples (RTT) or RTT differences (jitter) a gate needs.
pub const MIN_RTT_INPUTS: usize = 5;

/// The samples of the last rounds, oldest first.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Window {
    rounds: VecDeque<Vec<Sample>>,
}

/// Statistics of a window; a statistic without inputs is `None`, not zero.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Stats {
    pub samples: usize,
    pub lost: usize,
    pub loss: Option<f64>,
    /// Median RTT of the replied samples.
    pub rtt: Option<Duration>,
    pub replies: usize,
    /// Median absolute difference between consecutive RTTs of a target.
    pub jitter: Option<Duration>,
    pub differences: usize,
}

/// A violated gate, with the measured value.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Violation {
    Loss { value: f64, limit: f64 },
    Rtt { value: Duration, limit: Duration },
    Jitter { value: Duration, limit: Duration },
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ms = |d: &Duration| d.as_secs_f64() * 1000.0;
        match self {
            Violation::Loss { value, limit } => write!(f, "loss {value:.3} > {limit}"),
            Violation::Rtt { value, limit } => write!(f, "rtt {:.1} ms > {:.1} ms", ms(value), ms(limit)),
            Violation::Jitter { value, limit } => {
                write!(f, "jitter {:.1} ms > {:.1} ms", ms(value), ms(limit))
            }
        }
    }
}

impl Window {
    /// Adds a completed round's samples, keeping the last `capacity`
    /// rounds: a smaller `quality_window` drops the oldest rounds, a larger
    /// one grows from now on.
    pub fn push(&mut self, samples: Vec<Sample>, capacity: usize) {
        self.rounds.push_back(samples);
        while self.rounds.len() > capacity.max(1) {
            self.rounds.pop_front();
        }
    }

    pub fn clear(&mut self) {
        self.rounds.clear();
    }

    pub fn stats(&self) -> Stats {
        let all = self.rounds.iter().flatten();
        let samples = all.clone().count();
        let lost = all.clone().filter(|s| s.rtt.is_none()).count();
        let mut rtts: Vec<Duration> = all.clone().filter_map(|s| s.rtt).collect();
        // Consecutive RTTs of the same target, in the order they completed.
        let mut last: HashMap<Target, Duration> = HashMap::new();
        let mut differences = Vec::new();
        for s in all {
            if let Some(rtt) = s.rtt
                && let Some(prev) = last.insert(s.target, rtt)
            {
                differences.push(rtt.abs_diff(prev));
            }
        }
        Stats {
            samples,
            lost,
            loss: (samples > 0).then(|| lost as f64 / samples as f64),
            replies: rtts.len(),
            rtt: median(&mut rtts),
            differences: differences.len(),
            jitter: median(&mut differences),
        }
    }
}

/// The median; the mean of the two middle values for an even count.
fn median(values: &mut [Duration]) -> Option<Duration> {
    values.sort_unstable();
    let n = values.len();
    match n {
        0 => None,
        _ if n % 2 == 1 => Some(values[n / 2]),
        _ => Some((values[n / 2 - 1] + values[n / 2]) / 2),
    }
}

/// The gates `stats` violates: loss only with at least `min_samples`
/// samples, RTT and jitter only with [`MIN_RTT_INPUTS`] inputs.
pub fn violations(stats: &Stats, quality: &Quality, min_samples: u16) -> Vec<Violation> {
    let mut v = Vec::new();
    if let (Some(limit), Some(value)) = (quality.max_loss, stats.loss)
        && stats.samples >= usize::from(min_samples)
        && value > limit
    {
        v.push(Violation::Loss { value, limit });
    }
    if let (Some(limit), Some(value)) = (quality.max_rtt, stats.rtt)
        && stats.replies >= MIN_RTT_INPUTS
        && value > limit
    {
        v.push(Violation::Rtt { value, limit });
    }
    if let (Some(limit), Some(value)) = (quality.max_jitter, stats.jitter)
        && stats.differences >= MIN_RTT_INPUTS
        && value > limit
    {
        v.push(Violation::Jitter { value, limit });
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(n: u8) -> Target {
        Target::Icmp(std::net::IpAddr::from([192, 0, 2, n]))
    }

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    fn reply(t: u8, rtt: u64) -> Sample {
        Sample {
            target: target(t),
            rtt: Some(ms(rtt)),
        }
    }

    fn lost(t: u8) -> Sample {
        Sample {
            target: target(t),
            rtt: None,
        }
    }

    fn gates(loss: Option<f64>, rtt: Option<u64>, jitter: Option<u64>) -> Quality {
        Quality {
            max_loss: loss,
            max_rtt: rtt.map(ms),
            max_jitter: jitter.map(ms),
        }
    }

    #[test]
    fn an_empty_window_has_no_statistics() {
        let s = Window::default().stats();
        assert_eq!((s.samples, s.loss, s.rtt, s.jitter), (0, None, None, None));
        assert!(violations(&s, &gates(Some(0.0), Some(1), Some(1)), 1).is_empty());
    }

    #[test]
    fn one_echo_in_three_lost_violates_a_loss_gate_of_one_fifth() {
        // AS-06: every third echo is lost; a lost first attempt is followed
        // by a second one, which gets the reply.
        let mut w = Window::default();
        let mut n = 0u32;
        for _ in 0..6 {
            let mut round = Vec::new();
            for t in 1..=4 {
                n += 1;
                if n.is_multiple_of(3) {
                    round.push(lost(t));
                    n += 1;
                }
                round.push(reply(t, 10));
            }
            w.push(round, 6);
        }
        let s = w.stats();
        assert!(s.loss.unwrap() > 0.2, "{s:?}");
        let v = violations(&s, &gates(Some(0.2), None, None), 10);
        assert!(matches!(v[..], [Violation::Loss { .. }]), "{v:?}");
    }

    #[test]
    fn gates_need_enough_inputs() {
        let mut w = Window::default();
        w.push(vec![lost(1), reply(1, 500), reply(2, 500)], 6);
        let s = w.stats();
        assert_eq!((s.samples, s.lost, s.replies, s.differences), (3, 1, 2, 0));
        // 3 samples < quality_min_samples, 2 replies < 5: nothing evaluated.
        assert!(violations(&s, &gates(Some(0.0), Some(100), Some(0)), 10).is_empty());
        assert_eq!(violations(&s, &gates(Some(0.0), None, None), 3).len(), 1);
    }

    #[test]
    fn rtt_is_the_median_of_replies() {
        let mut w = Window::default();
        w.push(vec![reply(1, 10), reply(2, 40), reply(3, 20), lost(4)], 6);
        assert_eq!(w.stats().rtt, Some(ms(20)));
        w.push(vec![reply(4, 30)], 6);
        // Even count: the mean of 20 and 30.
        assert_eq!(w.stats().rtt, Some(ms(25)));
        for _ in 0..3 {
            w.push(vec![reply(1, 200)], 6);
        }
        let s = w.stats();
        assert_eq!((s.replies, s.rtt), (7, Some(ms(40))));
        let v = violations(&s, &gates(None, Some(25), None), 10);
        assert!(matches!(v[..], [Violation::Rtt { .. }]), "{v:?}");
        assert!(
            violations(&s, &gates(None, Some(40), None), 10).is_empty(),
            "the limit itself passes"
        );
    }

    #[test]
    fn jitter_compares_consecutive_rtts_of_the_same_target() {
        let mut w = Window::default();
        // Target 1 alternates 10/30 ms, target 2 is steady at 100 ms: the
        // spread between targets is not jitter.
        for i in 0..6u32 {
            w.push(
                vec![reply(1, if i.is_multiple_of(2) { 10 } else { 30 }), reply(2, 100)],
                6,
            );
        }
        let s = w.stats();
        // 5 differences of 20 ms (target 1), 5 of 0 (target 2).
        assert_eq!((s.differences, s.jitter), (10, Some(ms(10))));
        let steady: Vec<Sample> = (0..6).map(|_| reply(2, 100)).collect();
        let mut w2 = Window::default();
        for s in steady {
            w2.push(vec![s], 6);
        }
        assert_eq!(w2.stats().jitter, Some(Duration::ZERO));
        let v = violations(&s, &gates(None, None, Some(5)), 10);
        assert!(matches!(v[..], [Violation::Jitter { .. }]), "{v:?}");
    }

    #[test]
    fn the_window_keeps_the_last_rounds() {
        let mut w = Window::default();
        for _ in 0..6 {
            w.push(vec![lost(1)], 6);
        }
        assert_eq!(w.stats().loss, Some(1.0));
        // Recovery: old losses leave the window round by round.
        for k in 1..=6 {
            w.push(vec![reply(1, 10)], 6);
            assert_eq!(w.stats().lost, 6 - k);
        }
        // A smaller window drops the oldest rounds at the next round.
        for _ in 0..3 {
            w.push(vec![lost(1)], 6);
        }
        w.push(vec![reply(1, 10)], 2);
        assert_eq!((w.stats().samples, w.stats().lost), (2, 1));
        w.clear();
        assert_eq!(w.stats(), Stats::default());
    }
}
