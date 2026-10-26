//! Adapter lookup tables
//!
//! These tables hold the state of all tethers on an adapter, outbound (ELT) or inbound (DLT).
//!
//! RFC 6.5 § 5.1

#![allow(dead_code)]

use crate::defs::FiveTuple;
use crate::mgmt::txn_mgr::TxnHandle;
use crate::packet::Packet;
use crate::tc;
use crate::zdp;
use cslab::{RcuCslab, RcuCslabReader};
use dashmap::DashMap;
use dashmap::mapref::entry::Entry as DashMapEntry;
use dashmap::mapref::one::Ref as DashMapRef;
use rcu::{RcuBox, RcuCslabEntryGuard};
use std::sync::Mutex;
use zpr::packet_info::{CompressionMode, StreamId};

const DOCK_LOOKUP_TABLE_SIZE: usize = 1 << 20; // 1 million

pub struct EltPep {
    pub compression_mode: CompressionMode,
    pub tether_id: StreamId,
    pub a2a_shared_secret: Option<x25519_dalek::SharedSecret>,
    pub a2a_micv_key: Option<[u8; blake3::KEY_LEN]>,
}

impl EltPep {
    /// Constructor for an EltPep. The a2a_micv_key is derived from the a2a_shared_secret, if present.
    pub fn new(
        compression_mode: CompressionMode,
        tether_id: StreamId,
        a2a_shared_secret: Option<x25519_dalek::SharedSecret>,
    ) -> Self {
        let a2a_micv_key = a2a_shared_secret
            .as_ref()
            .map(|secret| blake3::derive_key(zdp::ZDP_A2A_MICV_KEY_CONTEXT, secret.as_bytes()));
        Self {
            compression_mode,
            tether_id,
            a2a_shared_secret,
            a2a_micv_key,
        }
    }
}

pub enum EltEntry {
    /// We've requested a tether ID for this flow, but haven't received one yet.
    Pending(Packet, TxnHandle),
    /// There is currently a tether allocated for this flow.
    Active(EltPep),
}

/// The Endpoint Lookup Table (ELT) holds all state of outbound tethers.
///
/// It is used to map five-tuples (from the endpoint) to compression
/// specifications and tether IDs (for the dock).
pub struct EndpointLookupTable {
    table: DashMap<FiveTuple, EltEntry>,
    pending: DashMap<TxnHandle, FiveTuple>,
}

pub struct EltEntryGuard<'a>(DashMapRef<'a, FiveTuple, EltEntry>);

impl std::ops::Deref for EltEntryGuard<'_> {
    type Target = EltEntry;

    fn deref(&self) -> &Self::Target {
        self.0.deref()
    }
}

pub enum InsertPendingError {
    AlreadyPending(Packet),
    DuplicateTransaction(Packet),
}

impl std::fmt::Debug for InsertPendingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        match self {
            Self::AlreadyPending(_) => write!(f, "AlreadyPending"),
            Self::DuplicateTransaction(_) => write!(f, "DuplicateTransaction"),
        }
    }
}

#[derive(Debug)]
pub enum LookupPendingError {
    NotFound,
    NotPending,
}

#[derive(Debug)]
pub enum RemoveError {
    NotFound,
}

pub enum SetActiveError {
    NotFound(EltPep),
    NotPending(EltPep),
}

impl std::fmt::Debug for SetActiveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        match self {
            Self::NotFound(_) => write!(f, "NotFound"),
            Self::NotPending(_) => write!(f, "NotPending"),
        }
    }
}

impl EndpointLookupTable {
    pub fn new() -> Self {
        Self {
            table: DashMap::new(),
            pending: DashMap::new(),
        }
    }

    pub fn insert_pending(
        &self,
        five_tuple: FiveTuple,
        init_packet: Packet,
        txn: &TxnHandle,
    ) -> Result<(), InsertPendingError> {
        match self.table.entry(five_tuple) {
            DashMapEntry::Occupied(_) => Err(InsertPendingError::AlreadyPending(init_packet)),

            DashMapEntry::Vacant(entry) => {
                if self.pending.insert(txn.clone(), five_tuple).is_some() {
                    return Err(InsertPendingError::DuplicateTransaction(init_packet));
                }
                entry.insert(EltEntry::Pending(init_packet, txn.clone()));
                Ok(())
            }
        }
    }

    pub fn lookup_pending(&self, txn: &TxnHandle) -> Result<FiveTuple, LookupPendingError> {
        Ok(*self.pending.get(txn).ok_or(LookupPendingError::NotFound)?)
    }

    pub fn set_active(
        &self,
        five_tuple: &FiveTuple,
        pep: EltPep,
    ) -> Result<Packet, SetActiveError> {
        let Some(mut entry) = self.table.get_mut(five_tuple) else {
            return Err(SetActiveError::NotFound(pep));
        };

        if !matches!(entry.value(), EltEntry::Pending(..)) {
            return Err(SetActiveError::NotPending(pep));
        }

        let EltEntry::Pending(packet, txn) =
            std::mem::replace(entry.value_mut(), EltEntry::Active(pep))
        else {
            unreachable!();
        };

        assert!(
            matches!(self.pending.remove(&txn), Some((_txn, ft)) if &ft == five_tuple),
            "ELT consistency error"
        );

        Ok(packet)
    }

    // TODO: figure out whether we want to perform partial matching
    pub fn inspect<T>(
        &self,
        five_tuple: &FiveTuple,
        inspector: impl FnOnce(&EltEntry) -> T,
    ) -> Option<T> {
        self.table.get(five_tuple).map(|entry| inspector(&*entry))
    }

    pub fn get(&self, five_tuple: &FiveTuple) -> Option<EltEntryGuard<'_>> {
        self.table.get(five_tuple).map(EltEntryGuard)
    }

    pub fn remove(&self, five_tuple: &FiveTuple) -> Result<EltEntry, RemoveError> {
        let (_, entry) = self.table.remove(five_tuple).ok_or(RemoveError::NotFound)?;

        match &entry {
            EltEntry::Pending(_, txn) => assert!(
                matches!(self.pending.remove(&txn), Some((_txn, ft)) if &ft == five_tuple),
                "ELT consistency error"
            ),
            EltEntry::Active(_) => (),
        }

        Ok(entry)
    }

    /// Remove every active entry bound to `tether_id`, returning how many were
    /// removed. Pending entries are left alone; they have no tether yet.
    pub fn remove_active_tether(&self, tether_id: StreamId) -> usize {
        let mut removed = 0;
        self.table.retain(|_, entry| match entry {
            EltEntry::Active(pep) if pep.tether_id == tether_id => {
                removed += 1;
                false
            }
            _ => true,
        });
        removed
    }

    /// Forget every outbound tether. Tether IDs are scoped to the dock link, so
    /// none survive a dock-link restart (DP-K01).
    pub fn clear(&self) {
        self.table.clear();
        self.pending.clear();
    }
}

pub struct DltPep {
    pub tc: tc::Ip5TupleTc,
    pub a2a_shared_secret: Option<x25519_dalek::SharedSecret>,
    pub a2a_micv_key: Option<[u8; blake3::KEY_LEN]>,
}

impl DltPep {
    /// Constructor for a DltPep. The a2a_micv_key is derived from the a2a_shared_secret, if present.
    pub fn new(tc: tc::Ip5TupleTc, a2a_shared_secret: Option<x25519_dalek::SharedSecret>) -> Self {
        let a2a_micv_key = a2a_shared_secret
            .as_ref()
            .map(|secret| blake3::derive_key(zdp::ZDP_A2A_MICV_KEY_CONTEXT, secret.as_bytes()));
        Self {
            tc,
            a2a_shared_secret,
            a2a_micv_key,
        }
    }
}

/// The Dock Lookup Table (DLT) holds all state of inbound tethers.
///
/// It is used to map tether IDs (from the dock) to decompression
/// specifications and five-tuples (for the endpoint).
pub struct DockLookupTable {
    table: Mutex<RcuCslab<DltPep>>,
    reader: RcuBox<RcuCslabReader<DltPep>>,
}

pub type DltPepGuard<'a> = RcuCslabEntryGuard<'a, DltPep>;

impl DockLookupTable {
    pub fn new() -> Self {
        let table = RcuCslab::with_fixed_capacity(DOCK_LOOKUP_TABLE_SIZE);
        let reader = table.reader();

        Self {
            table: Mutex::new(table),
            reader: RcuBox::new(reader),
        }
    }

    pub fn inspect<T>(
        &self,
        tether_id: StreamId,
        inspector: impl FnOnce(&DltPep) -> T,
    ) -> Option<T> {
        self.reader.inspect(|reader| {
            reader
                .get((tether_id as usize).wrapping_sub(1))
                .map(inspector)
        })
    }

    pub fn get(&self, tether_id: StreamId) -> Option<DltPepGuard<'_>> {
        self.reader
            .get_guarded((tether_id as usize).wrapping_sub(1))
    }

    pub fn insert(&self, pep: DltPep) -> Result<StreamId, ()> {
        Ok((self.table.lock().unwrap().insert(pep)? + 1) as StreamId)
    }

    pub fn remove(&self, tether_id: StreamId) {
        let mut table = self.table.lock().unwrap();
        let new_reader = table.remove((tether_id as usize).wrapping_sub(1));
        std::mem::drop(table);
        self.reader.write(new_reader);
    }
}

#[cfg(test)]
mod tests {
    use super::{EltEntry, EltPep, EndpointLookupTable};
    use crate::defs::FiveTuple;
    use crate::mgmt::core::new_heap_packet;
    use crate::mgmt::txn_mgr::TxnMgr;
    use futures::future::FutureExt;
    use std::sync::Arc;

    fn tuple(source_port: u16) -> FiveTuple {
        FiveTuple {
            src_port: source_port,
            ..FiveTuple::default()
        }
    }

    // DP-K01: a node withdrawal must drop only the entries bound to the
    // withdrawn tether, so the next packet on that flow re-binds.
    #[test]
    fn remove_active_tether_drops_only_matching_active_entries() {
        let mgr = Arc::new(TxnMgr::new());
        let elt = EndpointLookupTable::new();

        for (port, tether) in [(1, 7), (2, 8)] {
            let txn = mgr.open().now_or_never().unwrap();
            elt.insert_pending(tuple(port), new_heap_packet(), &txn)
                .unwrap();
            elt.set_active(&tuple(port), EltPep::new(0, tether, None))
                .unwrap();
        }
        let pending_txn = mgr.open().now_or_never().unwrap();
        elt.insert_pending(tuple(3), new_heap_packet(), &pending_txn)
            .unwrap();

        assert_eq!(elt.remove_active_tether(7), 1);
        assert!(elt.get(&tuple(1)).is_none());
        assert!(matches!(
            elt.inspect(&tuple(2), |e| matches!(e, EltEntry::Active(p) if p.tether_id == 8)),
            Some(true)
        ));
        assert!(elt.lookup_pending(&pending_txn).is_ok());

        assert_eq!(elt.remove_active_tether(7), 0);

        elt.clear();
        assert!(elt.get(&tuple(2)).is_none());
        assert!(elt.get(&tuple(3)).is_none());
        assert!(elt.lookup_pending(&pending_txn).is_err());
    }
}
