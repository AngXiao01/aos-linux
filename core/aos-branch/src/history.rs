use std::sync::Arc;

use aos_types::Object;

/// The versions of one object on one line of history (`main`, or a branch's
/// own writes), each tagged with the seq of the entry that wrote it. Versions
/// and seqs both increase.
#[derive(Clone, Debug, Default)]
pub(crate) struct History {
    versions: Vec<(u64, Arc<Object>)>,
}

impl History {
    pub fn push(&mut self, seq: u64, object: Arc<Object>) {
        debug_assert!(self.versions.last().is_none_or(|(s, o)| *s < seq && o.version < object.version));
        self.versions.push((seq, object));
    }

    pub fn last(&self) -> Option<&Arc<Object>> {
        self.versions.last().map(|(_, o)| o)
    }

    /// The latest version written by an entry with `seq < upto`.
    pub fn at(&self, upto: u64) -> Option<&Arc<Object>> {
        let i = self.versions.partition_point(|(s, _)| *s < upto);
        i.checked_sub(1).map(|i| &self.versions[i].1)
    }

    /// Version `v`, if it was written by an entry with `seq < upto`.
    pub fn version(&self, v: u64, upto: u64) -> Option<&Arc<Object>> {
        let i = self.versions.partition_point(|(_, o)| o.version < v);
        self.versions.get(i).filter(|(s, o)| o.version == v && *s < upto).map(|(_, o)| o)
    }

    /// Whether any version was written at or after `seq`.
    pub fn changed_since(&self, seq: u64) -> bool {
        self.versions.last().is_some_and(|(s, _)| *s >= seq)
    }

    pub fn upto(&self, upto: u64) -> impl Iterator<Item = &Arc<Object>> {
        self.versions.iter().take_while(move |(s, _)| *s < upto).map(|(_, o)| o)
    }
}
