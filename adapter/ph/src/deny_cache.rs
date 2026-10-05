//! Bounded node-side cache for explicit negative visa decisions.

use crate::config::MAX_DENIED_FLOW_BACKOFF_MS;
use crate::defs::FiveTuple;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const MAX_DENIED_FLOWS: usize = 4_096;
const MAX_DENIED_FLOWS_PER_LINK: usize = 128;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct DeniedFlowKey {
    ingress_link_id: u32,
    five_tuple: FiveTuple,
}

impl DeniedFlowKey {
    fn new(ingress_link_id: u32, five_tuple: &FiveTuple) -> Self {
        let mut normalized = *five_tuple;
        // Client reconnects commonly use a new ephemeral source port.
        normalized.src_port = 0;
        Self {
            ingress_link_id,
            five_tuple: normalized,
        }
    }
}

/// Stores bounded, short-lived denials; cache hits never authorize traffic.
pub struct DeniedFlowCache {
    default_backoff: Duration,
    entries: Mutex<HashMap<DeniedFlowKey, Instant>>,
}

impl DeniedFlowCache {
    /// Create a cache using the node-configured denial backoff.
    pub fn new(backoff_ms: u64) -> Self {
        Self {
            default_backoff: Duration::from_millis(backoff_ms.min(MAX_DENIED_FLOW_BACKOFF_MS)),
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// Return the remaining delay for a matching flow, removing expired entries.
    pub fn remaining(&self, ingress_link_id: u32, five_tuple: &FiveTuple) -> Option<Duration> {
        self.remaining_at(ingress_link_id, five_tuple, Instant::now())
    }

    fn remaining_at(
        &self,
        ingress_link_id: u32,
        five_tuple: &FiveTuple,
        now: Instant,
    ) -> Option<Duration> {
        let key = DeniedFlowKey::new(ingress_link_id, five_tuple);
        let mut entries = self.entries.lock().expect("denied-flow cache poisoned");
        match entries.get(&key).copied() {
            Some(expires_at) if expires_at > now => Some(expires_at - now),
            Some(_) => {
                entries.remove(&key);
                None
            }
            None => None,
        }
    }

    /// Cache an explicit Visa Service denial using the configured backoff.
    pub fn remember_denial(
        &self,
        ingress_link_id: u32,
        five_tuple: &FiveTuple,
    ) -> Option<Duration> {
        self.remember_for(ingress_link_id, five_tuple, self.default_backoff)
    }

    fn remember_for(
        &self,
        ingress_link_id: u32,
        five_tuple: &FiveTuple,
        backoff: Duration,
    ) -> Option<Duration> {
        self.remember_for_at(ingress_link_id, five_tuple, backoff, Instant::now())
    }

    fn remember_for_at(
        &self,
        ingress_link_id: u32,
        five_tuple: &FiveTuple,
        backoff: Duration,
        now: Instant,
    ) -> Option<Duration> {
        if backoff.is_zero() {
            return None;
        }

        let key = DeniedFlowKey::new(ingress_link_id, five_tuple);
        let mut entries = self.entries.lock().expect("denied-flow cache poisoned");
        entries.retain(|_, expires_at| *expires_at > now);

        ensure_capacity(&mut entries, ingress_link_id);
        entries.insert(key, now + backoff);
        Some(backoff)
    }
}

fn ensure_capacity(entries: &mut HashMap<DeniedFlowKey, Instant>, ingress_link_id: u32) {
    let link_count = entries
        .keys()
        .filter(|entry| entry.ingress_link_id == ingress_link_id)
        .count();
    if link_count >= MAX_DENIED_FLOWS_PER_LINK {
        evict_earliest(entries, |entry| entry.ingress_link_id == ingress_link_id);
    }
    if entries.len() >= MAX_DENIED_FLOWS {
        evict_earliest(entries, |_| true);
    }
}

fn evict_earliest(
    entries: &mut HashMap<DeniedFlowKey, Instant>,
    predicate: impl Fn(&DeniedFlowKey) -> bool,
) {
    if let Some(key) = entries
        .iter()
        .filter(|(key, _)| predicate(key))
        .min_by_key(|(_, expires_at)| **expires_at)
        .map(|(key, _)| *key)
    {
        entries.remove(&key);
    }
}

#[cfg(test)]
mod tests {
    use super::{DeniedFlowCache, MAX_DENIED_FLOWS_PER_LINK};
    use crate::defs::FiveTuple;
    use std::time::{Duration, Instant};

    fn tuple(source_port: u16, destination_port: u16) -> FiveTuple {
        let mut tuple = FiveTuple::default();
        tuple.src_port = source_port;
        tuple.dst_port = destination_port;
        tuple
    }

    #[test]
    fn source_port_changes_share_backoff_but_link_and_destination_port_do_not() {
        let cache = DeniedFlowCache::new(1_000);
        assert_eq!(
            cache.remember_denial(7, &tuple(40_000, 443)),
            Some(Duration::from_secs(1))
        );
        assert!(cache.remaining(7, &tuple(40_001, 443)).is_some());
        assert!(cache.remaining(8, &tuple(40_001, 443)).is_none());
        assert!(cache.remaining(7, &tuple(40_001, 8443)).is_none());
    }

    #[test]
    fn zero_backoff_disables_cache() {
        let cache = DeniedFlowCache::new(0);
        assert_eq!(cache.remember_denial(7, &tuple(40_000, 443)), None);
    }

    #[test]
    fn cache_only_matches_flows_after_an_explicit_denial() {
        let cache = DeniedFlowCache::new(1_000);
        let flow = tuple(40_000, 443);
        assert!(cache.remaining(7, &flow).is_none());
        assert_eq!(
            cache.remember_denial(7, &flow),
            Some(Duration::from_secs(1))
        );
        assert!(cache.remaining(7, &tuple(40_001, 443)).is_some());
    }

    #[test]
    fn expiry_allows_fresh_request_at_deadline() {
        let cache = DeniedFlowCache::new(500);
        let now = Instant::now();
        let flow = tuple(40_000, 443);
        assert_eq!(
            cache.remember_for_at(7, &flow, Duration::from_millis(500), now),
            Some(Duration::from_millis(500))
        );
        assert_eq!(
            cache.remaining_at(7, &flow, now + Duration::from_millis(499)),
            Some(Duration::from_millis(1))
        );
        assert_eq!(
            cache.remaining_at(7, &flow, now + Duration::from_millis(500)),
            None
        );
    }

    #[test]
    fn per_link_capacity_evicts_oldest_expiring_denial() {
        let cache = DeniedFlowCache::new(1_000);
        let now = Instant::now();
        for port in 1..=MAX_DENIED_FLOWS_PER_LINK as u16 + 1 {
            cache.remember_for_at(
                7,
                &tuple(port, port),
                Duration::from_secs(1),
                now + Duration::from_millis(port as u64),
            );
        }
        assert_eq!(
            cache.entries.lock().unwrap().len(),
            MAX_DENIED_FLOWS_PER_LINK
        );
        assert_eq!(cache.remaining_at(7, &tuple(1, 1), now), None);
        assert!(cache.remaining_at(7, &tuple(129, 129), now).is_some());
    }
}
