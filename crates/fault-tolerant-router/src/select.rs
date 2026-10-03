//! Active set selection (SPEC.md §4.4), per family.

use std::collections::BTreeSet;

use crate::config::AllDownPolicy;
use crate::model::UplinkId;

/// A candidate: an eligible (has a priority, not drained) and ready path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Candidate {
    pub uplink: UplinkId,
    pub priority: u16,
    pub healthy: bool,
}

/// Applies the decision table of §4.4 (FR-SEL-1).
pub fn active_set(
    candidates: &[Candidate],
    policy: AllDownPolicy,
    previous: &BTreeSet<UplinkId>,
) -> BTreeSet<UplinkId> {
    let best_group = |pool: &mut dyn Iterator<Item = &Candidate>| -> BTreeSet<UplinkId> {
        let pool: Vec<&Candidate> = pool.collect();
        let Some(best) = pool.iter().map(|c| c.priority).min() else {
            return BTreeSet::new();
        };
        pool.iter().filter(|c| c.priority == best).map(|c| c.uplink).collect()
    };
    if candidates.iter().any(|c| c.healthy) {
        return best_group(&mut candidates.iter().filter(|c| c.healthy));
    }
    match policy {
        AllDownPolicy::Ready => best_group(&mut candidates.iter()),
        AllDownPolicy::Keep => candidates
            .iter()
            .map(|c| c.uplink)
            .filter(|u| previous.contains(u))
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(id: u8, priority: u16, healthy: bool) -> Candidate {
        Candidate {
            uplink: UplinkId::new(id).unwrap(),
            priority,
            healthy,
        }
    }

    fn ids(v: &[u8]) -> BTreeSet<UplinkId> {
        v.iter().map(|i| UplinkId::new(*i).unwrap()).collect()
    }

    #[test]
    fn healthy_candidates_of_the_best_healthy_group() {
        let cands = [c(1, 1, false), c(2, 1, true), c(3, 1, true), c(4, 2, true)];
        assert_eq!(active_set(&cands, AllDownPolicy::Ready, &ids(&[])), ids(&[2, 3]));
        // Group 1 entirely down: group 2 takes over (AS-08).
        let cands = [c(1, 1, false), c(2, 1, false), c(4, 2, true), c(5, 3, true)];
        assert_eq!(active_set(&cands, AllDownPolicy::Keep, &ids(&[1])), ids(&[4]));
    }

    #[test]
    fn ready_policy_uses_the_best_group_regardless_of_health() {
        let cands = [c(3, 2, false), c(1, 1, false), c(2, 1, false)];
        assert_eq!(active_set(&cands, AllDownPolicy::Ready, &ids(&[3])), ids(&[1, 2]));
    }

    #[test]
    fn keep_policy_restricts_the_previous_set_to_current_candidates() {
        let cands = [c(1, 1, false), c(3, 2, false)];
        assert_eq!(active_set(&cands, AllDownPolicy::Keep, &ids(&[2, 3])), ids(&[3]));
        assert_eq!(active_set(&cands, AllDownPolicy::Keep, &ids(&[2])), ids(&[]));
    }

    #[test]
    fn no_candidate_means_an_empty_set() {
        assert!(active_set(&[], AllDownPolicy::Ready, &ids(&[1])).is_empty());
        assert!(active_set(&[], AllDownPolicy::Keep, &ids(&[1])).is_empty());
    }
}
