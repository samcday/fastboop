use anyhow::{Context, Result, anyhow, ensure};
use bitflags::bitflags;
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
};

const STATE_VERSION: u32 = 0;

bitflags! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
    pub struct ExportFlags: u32 {
        const READ_ONLY = 1 << 0;
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportSpec {
    pub block_size: u32,
    pub size_bytes: u64,
    pub flags: ExportFlags,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedExportRecord {
    pub export_id: u32,
    pub spec: ExportSpec,
    pub assigned_dev_id: Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PersistedState {
    version: u32,
    session_id: u64,
    exports: Vec<PersistedExportRecord>,
}

/// In-memory view of the persisted gadget state.
///
/// When `path` is `None`, persistence is disabled and `persist()` becomes a no-op.
#[derive(Clone, Debug)]
pub struct StateStore {
    path: Option<PathBuf>,
    session_id: u64,
    records: Vec<PersistedExportRecord>,
}

impl Default for StateStore {
    fn default() -> Self {
        Self::new()
    }
}

impl StateStore {
    /// Construct a fresh, in-memory store with a new session ID.
    pub fn new() -> Self {
        Self {
            path: None,
            session_id: generate_session_id(),
            records: Vec::new(),
        }
    }

    /// Construct a fresh, persistent store for `path` with a new session ID.
    pub fn new_with_path(path: PathBuf) -> Self {
        Self {
            path: Some(path),
            session_id: generate_session_id(),
            records: Vec::new(),
        }
    }

    /// Load state from `path`, returning an empty store with a new session ID when
    /// the file does not exist.
    pub fn load(path: PathBuf) -> Result<Self> {
        match fs::read(&path) {
            Ok(data) => {
                let state: PersistedState =
                    serde_json::from_slice(&data).context("decode state file")?;
                ensure!(
                    state.version == STATE_VERSION,
                    "unsupported state version {}",
                    state.version
                );
                Ok(Self {
                    path: Some(path),
                    session_id: state.session_id,
                    records: state.exports,
                })
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(Self {
                path: Some(path),
                session_id: generate_session_id(),
                records: Vec::new(),
            }),
            Err(err) => Err(err).context("read state file"),
        }
    }

    pub fn session_id(&self) -> u64 {
        self.session_id
    }

    pub fn records(&self) -> &[PersistedExportRecord] {
        &self.records
    }

    pub fn into_records(self) -> Vec<PersistedExportRecord> {
        self.records
    }

    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    pub fn replace_all(&mut self, records: Vec<PersistedExportRecord>) {
        self.records = records;
    }

    pub fn upsert_record(&mut self, record: PersistedExportRecord) {
        match self
            .records
            .iter()
            .position(|existing| existing.export_id == record.export_id)
        {
            Some(idx) => self.records[idx] = record,
            None => self.records.push(record),
        }
    }

    pub fn update_record<F>(&mut self, export_id: u32, f: F) -> Result<()>
    where
        F: FnOnce(&mut PersistedExportRecord),
    {
        let record = self
            .records
            .iter_mut()
            .find(|record| record.export_id == export_id)
            .ok_or_else(|| anyhow!("export {export_id} not found in state store"))?;
        f(record);
        Ok(())
    }

    pub fn remove_record(&mut self, export_id: u32) {
        if let Some(idx) = self
            .records
            .iter()
            .position(|record| record.export_id == export_id)
        {
            self.records.swap_remove(idx);
        }
    }

    /// Persist the current snapshot to disk. No-op when persistence is disabled.
    pub fn persist(&self) -> Result<()> {
        let Some(path) = &self.path else {
            return Ok(());
        };

        let state = PersistedState {
            version: STATE_VERSION,
            session_id: self.session_id,
            exports: self.records.clone(),
        };
        let payload = serde_json::to_vec(&state).context("encode state snapshot")?;
        let dir = path.parent().unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(dir).context("create state directory")?;
        let dir_file = File::open(dir).context("open state directory for sync")?;

        let tmp_path = path.with_extension("tmp");
        {
            let mut file = OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open(&tmp_path)
                .with_context(|| format!("open temporary state file {}", tmp_path.display()))?;
            file.write_all(&payload)
                .with_context(|| format!("write {}", tmp_path.display()))?;
            file.sync_all()
                .with_context(|| format!("flush {}", tmp_path.display()))?;
        }

        fs::rename(&tmp_path, path)
            .with_context(|| format!("commit state file to {}", path.display()))?;
        dir_file
            .sync_all()
            .context("sync state directory after rename")?;
        Ok(())
    }

    /// Remove the state file from disk, if persistence is enabled.
    pub fn remove_file(&self) -> Result<()> {
        let Some(path) = &self.path else {
            return Ok(());
        };

        match fs::remove_file(path) {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => {
                return Err(err).with_context(|| format!("remove state file {}", path.display()));
            }
        }

        if let Some(dir) = path.parent() {
            if let Ok(dir_file) = File::open(dir) {
                let _ = dir_file.sync_all();
            }
        }
        Ok(())
    }
}

fn generate_session_id() -> u64 {
    loop {
        let candidate = OsRng.next_u64();
        if candidate != 0 {
            return candidate;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn new_in_memory_has_session() {
        let store = StateStore::new();
        assert_ne!(store.session_id(), 0);
        assert!(store.path().is_none());
    }

    #[test]
    fn persist_round_trip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("state.json");
        let mut store = StateStore::load(path.clone()).unwrap();
        assert!(store.records().is_empty());

        let spec = ExportSpec {
            block_size: 4096,
            size_bytes: 4096 * 8,
            flags: ExportFlags::READ_ONLY,
        };
        let record = PersistedExportRecord {
            export_id: 1,
            spec,
            assigned_dev_id: Some(7),
        };
        store.upsert_record(record.clone());
        store.persist().unwrap();

        let loaded = StateStore::load(path).unwrap();
        assert_eq!(store.session_id(), loaded.session_id());
        assert_eq!(loaded.records(), &[record]);
    }

    #[test]
    fn load_missing_creates_new_session() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("missing.json");
        let store = StateStore::load(path).unwrap();
        assert!(store.records().is_empty());
        assert_ne!(store.session_id(), 0);
    }
}
