//! Storage behind the log. The log treats records as opaque bytes; a backend
//! only has to keep them in order and survive restarts. The file backend with
//! segments and CRCs (SPEC §A7) implements this trait in the platform layer.

use std::io;

pub trait LogStore {
    /// Number of records stored.
    fn len(&self) -> u64;

    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn read(&self, seq: u64) -> io::Result<Vec<u8>>;

    /// Appends records in order. May fail part-way; the log then refuses
    /// further appends until reopened, and recovery decides what survived.
    fn append(&mut self, records: &[Vec<u8>]) -> io::Result<()>;

    /// Makes appended records durable.
    fn sync(&mut self) -> io::Result<()>;

    /// Drops records from `len` on. Used only by recovery.
    fn truncate(&mut self, len: u64) -> io::Result<()>;
}

/// An in-memory backend with fault injection, for tests and simulations.
#[derive(Clone, Debug, Default)]
pub struct MemoryStore {
    records: Vec<Vec<u8>>,
    fail_after: Option<usize>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn records(&self) -> &[Vec<u8>] {
        &self.records
    }

    /// Direct access to stored bytes, for corrupting them in tests.
    pub fn records_mut(&mut self) -> &mut Vec<Vec<u8>> {
        &mut self.records
    }

    /// Makes the next append store only its first `n` records and then fail,
    /// as if the machine stopped mid-write.
    pub fn fail_next_append_after(&mut self, n: usize) {
        self.fail_after = Some(n);
    }
}

impl LogStore for MemoryStore {
    fn len(&self) -> u64 {
        self.records.len() as u64
    }

    fn read(&self, seq: u64) -> io::Result<Vec<u8>> {
        usize::try_from(seq)
            .ok()
            .and_then(|i| self.records.get(i))
            .cloned()
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, format!("no record {seq}")))
    }

    fn append(&mut self, records: &[Vec<u8>]) -> io::Result<()> {
        if let Some(n) = self.fail_after.take() {
            self.records.extend(records.iter().take(n).cloned());
            return Err(io::Error::other("injected failure"));
        }
        self.records.extend(records.iter().cloned());
        Ok(())
    }

    fn sync(&mut self) -> io::Result<()> {
        Ok(())
    }

    fn truncate(&mut self, len: u64) -> io::Result<()> {
        self.records.truncate(usize::try_from(len).map_err(io::Error::other)?);
        Ok(())
    }
}
