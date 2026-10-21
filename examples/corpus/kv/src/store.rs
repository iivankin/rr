//! A key-value store kept as a log on disk: every put and delete is a
//! record appended to the file, and an index in memory says where the
//! value of each live key is. Opening reads the log again to build the
//! index; a record cut short or damaged at the end, as a crash leaves
//! it, is cut off there. Compaction writes the live records to a new
//! file and puts it in the old one's place.

use alloc::collections::BTreeMap;
use alloc::collections::btree_map::Keys;
use alloc::vec::Vec;

use crate::record::{self, HEADER, KEY_MAX, Kind, RECORD_MAX, Read, VALUE_MAX};
use crate::sys::{self, File};

/// The most keys the store holds.
pub const KEYS_MAX: usize = 1 << 20;
/// The bytes read from the log at once when it is opened.
const CHUNK: usize = 1 << 16;

/// Why an operation failed.
pub enum Error {
    /// The system refused a call: the store is as it was before it.
    Sys,
    /// A key or value over its limit.
    TooLong,
    /// KEYS_MAX keys are held already.
    Full,
}

impl From<sys::Error> for Error {
    fn from(_: sys::Error) -> Error {
        Error::Sys
    }
}

/// Where a key's value is in the log.
pub struct Slot {
    at: u64,
    len: usize,
}

pub struct Store {
    file: File,
    path: Vec<u8>,
    /// Where the next record goes.
    end: u64,
    /// The live keys, each with where its value is.
    index: BTreeMap<Vec<u8>, Slot>,
    /// A value read for compaction, kept for the next.
    scratch: Vec<u8>,
}

impl Store {
    /// Open the store at path, made if it is missing.
    pub fn open(path: &[u8]) -> Result<Store, Error> {
        let file = File::open(path, false)?;
        let mut path_owned = Vec::with_capacity(path.len());
        // rr: escape(copy): compaction names the file again, after the caller's path is gone.
        path_owned.extend_from_slice(path);
        let mut s = Store {
            file,
            path: path_owned,
            end: 0,
            index: BTreeMap::new(),
            scratch: Vec::new(),
        };
        s.replay()?;
        Ok(s)
    }

    /// Read the log from the start into the index; cut off a record that
    /// is short or bad at its end.
    fn replay(&mut self) -> Result<(), Error> {
        let len = self.file.size()?;
        let mut buf: Vec<u8> = Vec::with_capacity(CHUNK + RECORD_MAX);
        // The log offset of buf's first byte, and how much of buf is read.
        let mut base = 0u64;
        let mut read_to = 0u64;
        loop {
            // Records whole in buf go into the index.
            let mut used = 0;
            let mut bad = false;
            while used < buf.len() {
                match record::read(&buf[used..]) {
                    Read::Whole(r, n) => {
                        let at = base + (used + HEADER + r.key.len()) as u64;
                        self.apply(&r.kind, r.key, at, r.value.len())?;
                        used += n;
                    }
                    Read::Short => break,
                    Read::Bad => {
                        bad = true;
                        break;
                    }
                }
            }
            base += used as u64;
            buf.drain(..used);
            if bad || read_to == len {
                break;
            }
            // More of the log after what is left.
            let start = buf.len();
            let want = CHUNK.min(usize::try_from(len - read_to).unwrap_or(CHUNK));
            buf.resize(start + want, 0);
            let n = self.file.read_at(read_to, &mut buf[start..])?;
            buf.truncate(start + n);
            if n == 0 {
                break;
            }
            read_to += n as u64;
        }
        // What follows the last whole record is a crash's leftover.
        if base < len {
            self.file.truncate(base)?;
        }
        self.end = base;
        Ok(())
    }

    /// A record read from the log, put into the index; its value is at at.
    fn apply(&mut self, kind: &Kind, key: &[u8], at: u64, len: usize) -> Result<(), Error> {
        match kind {
            Kind::Put => self.place(key, Slot { at, len }),
            Kind::Delete => {
                self.index.remove(key);
                Ok(())
            }
        }
    }

    /// key's value is at slot from now on.
    fn place(&mut self, key: &[u8], slot: Slot) -> Result<(), Error> {
        if let Some(s) = self.index.get_mut(key) {
            *s = slot;
            return Ok(());
        }
        if self.index.len() >= KEYS_MAX {
            return Err(Error::Full);
        }
        // rr: escape(copy): the index keeps each key it holds.
        self.index.insert(key.to_vec(), slot);
        Ok(())
    }

    /// Append a record of kind for key and value; where the value went.
    fn append(&mut self, kind: &Kind, key: &[u8], value: &[u8]) -> Result<u64, Error> {
        if key.len() > KEY_MAX || value.len() > VALUE_MAX {
            return Err(Error::TooLong);
        }
        let h = record::header(kind, key, value);
        let start = self.end;
        self.file.write_at(start, &h)?;
        self.file.write_at(start + HEADER as u64, key)?;
        let at = start + (HEADER + key.len()) as u64;
        self.file.write_at(at, value)?;
        self.end = at + value.len() as u64;
        Ok(at)
    }

    /// Set key to value.
    #[cfg_attr(rr, rr::hot)]
    pub fn put(&mut self, key: &[u8], value: &[u8]) -> Result<(), Error> {
        if !self.index.contains_key(key) && self.index.len() >= KEYS_MAX {
            return Err(Error::Full);
        }
        let at = self.append(&Kind::Put, key, value)?;
        self.place(
            key,
            Slot {
                at,
                len: value.len(),
            },
        )
    }

    /// key's value into out; false when the key is not held.
    #[cfg_attr(rr, rr::hot)]
    pub fn get(&self, key: &[u8], out: &mut Vec<u8>) -> Result<bool, Error> {
        out.clear();
        let Some(slot) = self.index.get(key) else {
            return Ok(false);
        };
        let len = slot.len;
        out.resize(len, 0);
        let mut got = 0;
        while got < len {
            let n = self.file.read_at(slot.at + got as u64, &mut out[got..])?;
            if n == 0 {
                return Err(Error::Sys);
            }
            got += n;
        }
        Ok(true)
    }

    /// Remove key; false when it was not held.
    #[cfg_attr(rr, rr::hot)]
    pub fn delete(&mut self, key: &[u8]) -> Result<bool, Error> {
        if !self.index.contains_key(key) {
            return Ok(false);
        }
        self.append(&Kind::Delete, key, &[])?;
        self.index.remove(key);
        Ok(true)
    }

    /// The live keys, in order.
    pub fn keys(&self) -> Keys<'_, Vec<u8>, Slot> {
        self.index.keys()
    }

    /// Write the live records to a new log and put it in the old one's
    /// place; the store is unchanged if that fails.
    pub fn compact(&mut self) -> Result<(), Error> {
        let mut tmp = Vec::with_capacity(self.path.len() + 4);
        tmp.extend_from_slice(&self.path);
        tmp.extend_from_slice(b".tmp");
        let new = File::open(&tmp, true)?;
        let mut end = 0u64;
        let mut moved: Vec<u64> = Vec::with_capacity(self.index.len());
        for (key, slot) in &self.index {
            let len = slot.len;
            self.scratch.clear();
            self.scratch.resize(len, 0);
            let n = self.file.read_at(slot.at, &mut self.scratch)?;
            if n != len {
                // rr: escape(discard): a leftover temporary file is emptied by the next compaction.
                let _: Result<(), sys::Error> = sys::remove(&tmp);
                return Err(Error::Sys);
            }
            let h = record::header(&Kind::Put, key, &self.scratch);
            new.write_at(end, &h)?;
            new.write_at(end + HEADER as u64, key)?;
            let at = end + (HEADER + key.len()) as u64;
            new.write_at(at, &self.scratch)?;
            moved.push(at);
            end = at + len as u64;
        }
        new.sync()?;
        // Windows gives a file a name only when nothing holds open the one
        // it replaces: the old log closes first, and opens again, whole as
        // it was, if the rename fails.
        drop(core::mem::replace(&mut self.file, new));
        if sys::rename_to(&tmp, &self.path).is_err() {
            self.file = File::open(&self.path, false)?;
            return Err(Error::Sys);
        }
        for (slot, at) in self.index.values_mut().zip(moved) {
            slot.at = at;
        }
        self.end = end;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::Store;
    use crate::sys::{self, File};
    use alloc::vec::Vec;
    use test::Bencher;

    /// A store at path, made afresh.
    fn fresh(path: &[u8]) -> Store {
        // rr: escape(discard): the file may not be there yet.
        let _: Result<(), sys::Error> = sys::remove(path);
        reopen(path)
    }

    /// The store closed and its file removed: a test leaves nothing.
    fn gone(s: Store, path: &[u8]) {
        drop(s);
        assert!(sys::remove(path).is_ok());
    }

    fn reopen(path: &[u8]) -> Store {
        let Ok(s) = Store::open(path) else {
            panic!("open");
        };
        s
    }

    fn value(s: &Store, key: &[u8]) -> Option<Vec<u8>> {
        let mut out = Vec::new();
        let Ok(held) = s.get(key, &mut out) else {
            panic!("get");
        };
        held.then_some(out)
    }

    #[test]
    fn put_get_delete() {
        let path = b"kv-test-put.log";
        let mut s = fresh(path);
        assert!(s.put(b"a", b"1").is_ok());
        assert!(s.put(b"b", b"2").is_ok());
        assert!(s.put(b"a", b"3").is_ok());
        assert_eq!(value(&s, b"a").as_deref(), Some(&b"3"[..]));
        assert!(s.delete(b"b").is_ok_and(|held| held));
        assert!(value(&s, b"b").is_none());
        assert!(s.delete(b"b").is_ok_and(|held| !held));
        gone(s, path);
    }

    #[test]
    fn too_long_is_refused() {
        let path = b"kv-test-long.log";
        let mut s = fresh(path);
        assert!(s.put(&[b'k'; 256], b"v").is_err());
        let mut big = Vec::new();
        big.resize(65537, 0);
        assert!(s.put(b"k", &big).is_err());
        assert!(value(&s, b"k").is_none());
        gone(s, path);
    }

    /// Reopened, the log says the same.
    #[test]
    fn replays_its_log() {
        let path = b"kv-test-replay.log";
        let mut s = fresh(path);
        assert!(s.put(b"a", b"3").is_ok());
        assert!(s.put(b"b", b"2").is_ok());
        assert!(s.delete(b"b").is_ok());
        drop(s);
        let again = reopen(path);
        assert_eq!(value(&again, b"a").as_deref(), Some(&b"3"[..]));
        assert!(value(&again, b"b").is_none());
        assert_eq!(again.index.len(), 1);
        gone(again, path);
    }

    /// A crash cuts the last record short: it is dropped, the rest kept.
    #[test]
    fn cuts_a_short_record_off() {
        let path = b"kv-test-cut.log";
        let mut s = fresh(path);
        assert!(s.put(b"a", b"3").is_ok());
        assert!(s.put(b"c", b"hello").is_ok());
        drop(s);
        let Ok(f) = File::open(path, false) else {
            panic!("reopen file");
        };
        let Ok(len) = f.size() else {
            panic!("size");
        };
        assert!(f.truncate(len - 2).is_ok());
        drop(f);
        let again = reopen(path);
        assert!(value(&again, b"c").is_none());
        assert_eq!(value(&again, b"a").as_deref(), Some(&b"3"[..]));
        gone(again, path);
    }

    /// Compaction keeps live keys only, and their values.
    #[test]
    fn compaction_keeps_live_keys() {
        let path = b"kv-test-compact.log";
        let mut s = fresh(path);
        for i in 0..100u8 {
            assert!(s.put(&[b'k', i], &[i; 40]).is_ok());
        }
        for i in 0..50u8 {
            assert!(s.delete(&[b'k', i]).is_ok());
        }
        assert!(s.compact().is_ok());
        assert_eq!(s.index.len(), 50);
        assert_eq!(value(&s, &[b'k', 99]).as_deref(), Some(&[99u8; 40][..]));
        drop(s);
        let again = reopen(path);
        assert_eq!(again.index.len(), 50);
        assert!(value(&again, &[b'k', 0]).is_none());
        gone(again, path);
    }

    /// A value read into a buffer that is reused: no allocation.
    #[bench]
    fn get_into_one_buffer(b: &mut Bencher) {
        let path = b"kv-bench-get.log";
        let mut s = fresh(path);
        assert!(s.put(b"key", &[7; 100]).is_ok());
        let mut out = Vec::new();
        b.iter(|| s.get(b"key", &mut out).is_ok());
        gone(s, path);
    }
}
