//! Health state machine of a path (SPEC.md §5.3).

use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum State {
    Down,
    Up,
}

/// Reason of a transition (FR-HEALTH-4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Reason {
    ProbeFailed,
    Degraded,
    CarrierLost,
    InterfaceRemoved,
    AddressLost,
    AddressConflict,
    GatewayLost,
    RouteInstallFailed,
    ProbesRecovered,
    Startup,
}

impl Reason {
    pub fn as_str(self) -> &'static str {
        match self {
            Reason::ProbeFailed => "probe_failed",
            Reason::Degraded => "degraded",
            Reason::CarrierLost => "carrier_lost",
            Reason::InterfaceRemoved => "interface_removed",
            Reason::AddressLost => "address_lost",
            Reason::AddressConflict => "address_conflict",
            Reason::GatewayLost => "gateway_lost",
            Reason::RouteInstallFailed => "route_install_failed",
            Reason::ProbesRecovered => "probes_recovered",
            Reason::Startup => "startup",
        }
    }
}

impl fmt::Display for Reason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Outcome of a completed probe round (FR-PROBE-4, FR-PROBE-5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Round {
    Passed,
    Failed,
    /// Passed reachability but violated a quality gate.
    Degraded,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Transition {
    pub from: State,
    pub to: State,
    pub reason: Reason,
}

/// Hysteresis settings (FR-HEALTH-2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hysteresis {
    pub fall: u8,
    pub rise: u8,
}

/// Checkpointed part of the machine (IMPL-5 health checkpoint).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub state: State,
    pub passes: u8,
    pub failures: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Machine {
    state: State,
    reason: Reason,
    passes: u8,
    failures: u8,
    /// Cold start: the first completed round sets the state directly.
    optimistic: bool,
    ready: bool,
}

impl Machine {
    /// FR-HEALTH-1. `ready` is applied first: a path that is not ready starts
    /// `down`. `warm` is a checkpoint from the same boot taken less than 10
    /// minutes earlier, already matched to this path's identity.
    pub fn new(ready: bool, not_ready_reason: Reason, warm: Option<Snapshot>) -> Machine {
        match (ready, warm) {
            (false, _) => Machine {
                state: State::Down,
                reason: not_ready_reason,
                passes: 0,
                failures: 0,
                optimistic: false,
                ready: false,
            },
            (true, Some(s)) => Machine {
                state: s.state,
                reason: Reason::Startup,
                passes: s.passes,
                failures: s.failures,
                optimistic: false,
                ready: true,
            },
            (true, None) => Machine {
                state: State::Up,
                reason: Reason::Startup,
                passes: 0,
                failures: 0,
                optimistic: true,
                ready: true,
            },
        }
    }

    pub fn state(&self) -> State {
        self.state
    }

    pub fn reason(&self) -> Reason {
        self.reason
    }

    pub fn is_ready(&self) -> bool {
        self.ready
    }

    pub fn is_up(&self) -> bool {
        self.state == State::Up
    }

    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            state: self.state,
            passes: self.passes,
            failures: self.failures,
        }
    }

    fn go(&mut self, to: State, reason: Reason) -> Option<Transition> {
        self.reason = reason;
        if self.state == to {
            return None;
        }
        let from = self.state;
        self.state = to;
        Some(Transition { from, to, reason })
    }

    /// Readiness change (FR-HEALTH-3): losing readiness is immediate; a path
    /// that becomes ready again starts `down` and needs `rise` passed rounds.
    pub fn set_ready(&mut self, ready: bool, reason: Reason) -> Option<Transition> {
        if ready == self.ready {
            return None;
        }
        self.ready = ready;
        self.passes = 0;
        self.failures = 0;
        self.optimistic = false;
        if ready { None } else { self.go(State::Down, reason) }
    }

    /// A completed round (FR-HEALTH-2). Rounds of a path that is not ready
    /// are ignored; the prober is stopped in that case anyway.
    pub fn round(&mut self, round: Round, h: Hysteresis) -> Option<Transition> {
        if !self.ready {
            return None;
        }
        let failure_reason = |r| {
            if r == Round::Degraded {
                Reason::Degraded
            } else {
                Reason::ProbeFailed
            }
        };
        if self.optimistic {
            self.optimistic = false;
            return match round {
                Round::Passed => {
                    self.passes = 1;
                    None
                }
                r => {
                    self.failures = 1;
                    self.go(State::Down, failure_reason(r))
                }
            };
        }
        match round {
            Round::Passed => {
                self.failures = 0;
                self.passes = self.passes.saturating_add(1);
                if self.state == State::Down && self.passes >= h.rise {
                    return self.go(State::Up, Reason::ProbesRecovered);
                }
            }
            r => {
                self.passes = 0;
                self.failures = self.failures.saturating_add(1);
                if self.state == State::Up && self.failures >= h.fall {
                    return self.go(State::Down, failure_reason(r));
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const H: Hysteresis = Hysteresis { fall: 2, rise: 3 };

    #[test]
    fn cold_start_is_optimistic_and_the_first_round_decides() {
        let mut m = Machine::new(true, Reason::Startup, None);
        assert!(m.is_up());
        let t = m.round(Round::Failed, H).unwrap();
        assert_eq!((t.to, t.reason), (State::Down, Reason::ProbeFailed));
        let mut m = Machine::new(true, Reason::Startup, None);
        assert_eq!(m.round(Round::Passed, H), None);
        // After the first round, normal hysteresis.
        assert_eq!(m.round(Round::Failed, H), None);
        assert_eq!(m.round(Round::Failed, H).map(|t| t.to), Some(State::Down));
    }

    #[test]
    fn not_ready_starts_down_with_its_reason() {
        let m = Machine::new(false, Reason::CarrierLost, None);
        assert_eq!((m.state(), m.reason()), (State::Down, Reason::CarrierLost));
    }

    #[test]
    fn warm_start_resumes_the_checkpoint() {
        let snap = Snapshot {
            state: State::Down,
            passes: 2,
            failures: 0,
        };
        let mut m = Machine::new(true, Reason::Startup, Some(snap));
        assert!(!m.is_up());
        let t = m.round(Round::Passed, H).unwrap();
        assert_eq!((t.to, t.reason), (State::Up, Reason::ProbesRecovered));
    }

    #[test]
    fn hysteresis_needs_fall_and_rise_consecutive_rounds() {
        let mut m = Machine::new(
            true,
            Reason::Startup,
            Some(Snapshot {
                state: State::Up,
                passes: 0,
                failures: 0,
            }),
        );
        assert_eq!(m.round(Round::Failed, H), None);
        assert_eq!(m.round(Round::Passed, H), None);
        assert_eq!(m.round(Round::Failed, H), None);
        let t = m.round(Round::Degraded, H).unwrap();
        assert_eq!(t.reason, Reason::Degraded);
        assert_eq!(m.round(Round::Passed, H), None);
        assert_eq!(m.round(Round::Passed, H), None);
        assert_eq!(m.round(Round::Failed, H), None);
        assert_eq!(m.round(Round::Passed, H), None);
        assert_eq!(m.round(Round::Passed, H), None);
        assert_eq!(m.round(Round::Passed, H).map(|t| t.to), Some(State::Up));
    }

    #[test]
    fn readiness_loss_is_immediate_and_recovery_needs_rise() {
        let mut m = Machine::new(true, Reason::Startup, None);
        let t = m.set_ready(false, Reason::CarrierLost).unwrap();
        assert_eq!((t.from, t.to, t.reason), (State::Up, State::Down, Reason::CarrierLost));
        assert_eq!(
            m.round(Round::Passed, H),
            None,
            "rounds of a path that is not ready are ignored"
        );
        assert_eq!(m.set_ready(true, Reason::Startup), None);
        assert!(!m.is_up(), "startup optimism applies only to cold start");
        assert_eq!(m.round(Round::Passed, H), None);
        assert_eq!(m.round(Round::Passed, H), None);
        assert_eq!(
            m.round(Round::Passed, H).map(|t| t.reason),
            Some(Reason::ProbesRecovered)
        );
    }
}
