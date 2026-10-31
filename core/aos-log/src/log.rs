//! The hash-chained log: verification on open, recovery of an unfinished
//! commit group, and appends.

use std::fmt;
use std::io;

use aos_types::codec;
use aos_types::{Digest, Timestamp};

use crate::entry::{Body, BranchName, Entry, GENESIS};
use crate::store::LogStore;

/// The log's length and last hash, kept outside the log so that dropping
/// entries from the end is detectable (SPEC §7.7 keeps hash-chain anchors).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Anchor {
    pub len: u64,
    pub head: Digest,
}

#[derive(Debug)]
pub enum Corruption {
    Undecodable(codec::Error),
    WrongSeq,
    BrokenChain,
    HashMismatch,
    BadGroup(&'static str),
}

#[derive(Debug)]
pub enum OpenError {
    Io(io::Error),
    /// Entry `seq` was altered or damaged. The caller should enter read-only
    /// safe mode (SPEC §A10 S4).
    Corrupt {
        seq: u64,
        reason: Corruption,
    },
    /// The log does not extend the anchor it was opened with: entries were
    /// removed or rewritten.
    AnchorMismatch,
}

impl fmt::Display for OpenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OpenError::Io(e) => write!(f, "log I/O: {e}"),
            OpenError::Corrupt { seq, reason } => write!(f, "log entry {seq} is corrupt: {reason:?}"),
            OpenError::AnchorMismatch => f.write_str("log does not extend its anchor"),
        }
    }
}

impl std::error::Error for OpenError {}

impl From<io::Error> for OpenError {
    fn from(e: io::Error) -> Self {
        OpenError::Io(e)
    }
}

/// What recovery did while opening.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Recovery {
    /// Entries of an unfinished commit group removed from the end.
    pub dropped: u64,
}

pub struct Log<S> {
    store: S,
    /// Hash of every entry, by seq.
    hashes: Vec<Digest>,
    /// Set when an append failed part-way; the stored tail is then unknown
    /// until the log is reopened.
    poisoned: bool,
}

impl<S: LogStore> Log<S> {
    /// Verifies every entry: sequence numbers, hash chain, stored hashes and
    /// commit-group structure. An unfinished group at the end is the trace
    /// of a crash during commit and is removed; anything else wrong is
    /// corruption.
    pub fn open(store: S, anchor: Option<Anchor>) -> Result<(Self, Recovery), OpenError> {
        Self::open_with_entries(store, anchor).map(|(log, recovery, _)| (log, recovery))
    }

    /// Like [`Log::open`], also returning the verified entries, so a caller
    /// rebuilding an index does not decode the log twice.
    pub fn open_with_entries(mut store: S, anchor: Option<Anchor>) -> Result<(Self, Recovery, Vec<Entry>), OpenError> {
        let len = store.len();
        let mut entries = Vec::with_capacity(usize::try_from(len).unwrap_or(0));
        let mut hashes = Vec::with_capacity(usize::try_from(len).unwrap_or(0));
        let mut head = GENESIS;
        // (branch, first seq, tx count)
        let mut group: Option<(BranchName, u64, u64)> = None;
        for seq in 0..len {
            let corrupt = |reason| OpenError::Corrupt { seq, reason };
            let d = Entry::decode(&store.read(seq)?).map_err(|e| corrupt(Corruption::Undecodable(e)))?;
            if d.entry.seq != seq {
                return Err(corrupt(Corruption::WrongSeq));
            }
            if d.entry.prev_hash != head {
                return Err(corrupt(Corruption::BrokenChain));
            }
            if d.computed_hash != d.stored_hash {
                return Err(corrupt(Corruption::HashMismatch));
            }
            group = match (group, &d.entry.body) {
                (None, Body::Tx(tx)) if tx.merged_from.is_some() => {
                    Some((tx.merged_from.clone().expect("checked"), seq, 1))
                }
                (Some((b, start, n)), Body::Tx(tx)) if tx.merged_from.as_ref() == Some(&b) => Some((b, start, n + 1)),
                (Some((b, _, n)), Body::Commit { branch, txs, .. }) if *branch == b && *txs == n => None,
                (None, Body::Commit { txs: 0, .. }) => None,
                (Some(_), _) => return Err(corrupt(Corruption::BadGroup("group interrupted"))),
                (None, Body::Commit { .. }) => return Err(corrupt(Corruption::BadGroup("commit without its group"))),
                (None, _) => None,
            };
            head = d.stored_hash;
            hashes.push(head);
            entries.push(d.entry);
        }
        let mut recovery = Recovery::default();
        if let Some((_, start, _)) = group {
            store.truncate(start)?;
            store.sync()?;
            recovery.dropped = len - start;
            hashes.truncate(start as usize);
            entries.truncate(start as usize);
        }
        if let Some(a) = anchor
            && a.len > 0
            && hashes.get(a.len as usize - 1) != Some(&a.head)
        {
            return Err(OpenError::AnchorMismatch);
        }
        Ok((Log { store, hashes, poisoned: false }, recovery, entries))
    }

    pub fn len(&self) -> u64 {
        self.hashes.len() as u64
    }

    pub fn is_empty(&self) -> bool {
        self.hashes.is_empty()
    }

    /// Hash of the last entry ([`GENESIS`] when empty).
    pub fn head(&self) -> Digest {
        self.hashes.last().copied().unwrap_or(GENESIS)
    }

    /// Hash of entry `seq`, if it exists.
    pub fn hash_of(&self, seq: u64) -> Option<Digest> {
        usize::try_from(seq).ok().and_then(|i| self.hashes.get(i)).copied()
    }

    pub fn anchor(&self) -> Anchor {
        Anchor { len: self.len(), head: self.head() }
    }

    /// Appends `bodies` as consecutive entries and syncs. Either all are
    /// appended or the log is poisoned and must be reopened.
    pub fn append(&mut self, timestamp: Timestamp, bodies: Vec<Body>) -> io::Result<Vec<Entry>> {
        if self.poisoned {
            return Err(io::Error::other("log poisoned by an earlier failed append; reopen it"));
        }
        let mut head = self.head();
        let mut entries = Vec::with_capacity(bodies.len());
        let mut records = Vec::with_capacity(bodies.len());
        let mut hashes = Vec::with_capacity(bodies.len());
        for (i, body) in bodies.into_iter().enumerate() {
            let entry = Entry { seq: self.len() + i as u64, prev_hash: head, timestamp, body };
            let (bytes, hash) = entry.encode();
            head = hash;
            records.push(bytes);
            hashes.push(hash);
            entries.push(entry);
        }
        if let Err(e) = self.store.append(&records).and_then(|()| self.store.sync()) {
            self.poisoned = true;
            return Err(e);
        }
        self.hashes.extend(hashes);
        Ok(entries)
    }

    /// Reads and checks one entry against its stored hash.
    pub fn read(&self, seq: u64) -> Result<Entry, OpenError> {
        if seq >= self.len() {
            return Err(OpenError::Io(io::Error::new(io::ErrorKind::UnexpectedEof, format!("no entry {seq}"))));
        }
        let d = Entry::decode(&self.store.read(seq)?)
            .map_err(|e| OpenError::Corrupt { seq, reason: Corruption::Undecodable(e) })?;
        if d.computed_hash != d.stored_hash || d.entry.seq != seq {
            return Err(OpenError::Corrupt { seq, reason: Corruption::HashMismatch });
        }
        Ok(d.entry)
    }

    pub fn entries(&self) -> impl Iterator<Item = Result<Entry, OpenError>> + '_ {
        (0..self.len()).map(|seq| self.read(seq))
    }

    pub fn store(&self) -> &S {
        &self.store
    }

    pub fn into_store(self) -> S {
        self.store
    }
}
