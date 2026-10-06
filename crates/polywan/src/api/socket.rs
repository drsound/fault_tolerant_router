//! Unix sockets of the API (SPEC.md FR-API-1): set up without a transiently
//! permissive socket, published by rename, never over a foreign object.
//!
//! A socket is bound in a private staging directory next to its path, given
//! its final owner, group and mode there, then renamed into place. An
//! existing object at the path is replaced only if it is a socket that this
//! instance published or that the protected record of published sockets
//! (in the runtime directory, root-only) identifies by device and inode;
//! anything else, including a symbolic link, is refused and left alone.

use std::fs;
use std::io;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::checks;

/// A socket that PolyWAN published.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Published {
    pub path: PathBuf,
    pub dev: u64,
    pub ino: u64,
}

/// The record of published sockets, in the runtime directory.
#[derive(Clone, Debug)]
pub struct Record {
    file: PathBuf,
}

const RECORD: &str = "sockets.json";

impl Record {
    pub fn new(runtime_dir: &Path) -> Record {
        Record {
            file: runtime_dir.join(RECORD),
        }
    }

    /// The published sockets; a record that is not a root-owned regular
    /// file without group or other permissions is no evidence.
    pub fn read(&self) -> Vec<Published> {
        let Ok(m) = fs::symlink_metadata(&self.file) else {
            return Vec::new();
        };
        if !m.is_file() || m.uid() != 0 || m.mode() & 0o077 != 0 {
            return Vec::new();
        }
        fs::read(&self.file)
            .ok()
            .and_then(|t| serde_json::from_slice(&t).ok())
            .unwrap_or_default()
    }

    pub fn write(&self, sockets: &[Published]) -> io::Result<()> {
        let text = serde_json::to_vec(sockets).map_err(io::Error::other)?;
        // Mode 0600, as every file written atomically.
        crate::state::write_atomic(&self.file, &text).map_err(io::Error::other)
    }
}

/// Who may connect: mode 0660 with a group, or 0666 for everyone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Access {
    pub gid: Option<u32>,
}

impl Access {
    pub fn mode(self) -> u32 {
        if self.gid.is_some() { 0o660 } else { 0o666 }
    }
}

/// The private directory a socket is staged in, next to its path, named
/// after the process.
const STAGING: &str = ".polywan-staging-";
/// The socket's name in the staging directory.
const STAGED: &str = "s";

/// The most that staging adds to the path of a socket's directory: the
/// staging directory of the largest process id and the staged socket
/// (FR-API-1: the staged path must fit `sun_path` too).
pub const STAGING_SUFFIX_MAX: usize = 1 + STAGING.len() + (u32::MAX.ilog10() + 1) as usize + 1 + STAGED.len();

fn staging(parent: &Path) -> PathBuf {
    parent.join(format!("{STAGING}{}", std::process::id()))
}

/// Gives a socket its owner, group and mode (FR-API-1).
pub fn apply_access(path: &Path, access: Access) -> io::Result<()> {
    std::os::unix::fs::chown(path, Some(0), Some(access.gid.unwrap_or(0)))?;
    fs::set_permissions(path, fs::Permissions::from_mode(access.mode()))
}

/// Binds the listener of `path` with `access` (FR-API-1). `known` lists the
/// sockets this instance or the record identifies as PolyWAN's.
pub fn bind(
    path: &Path,
    access: Access,
    known: &[Published],
) -> io::Result<(std::os::unix::net::UnixListener, Published)> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::other(format!("{}: no parent directory", path.display())))?;
    // The directory must be root's alone, also through symbolic links.
    let trust = checks::ownership(parent, "api socket directory");
    if let Some(e) = trust.errors.first() {
        return Err(io::Error::other(e.clone()));
    }
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
        Ok(m) => {
            let ours = m.file_type().is_socket()
                && known
                    .iter()
                    .any(|k| k.path == path && k.dev == m.dev() && k.ino == m.ino());
            if !ours {
                return Err(io::Error::other(format!(
                    "{} is occupied by an object PolyWAN cannot identify as its own; remove it if it is a stale socket (FR-API-1)",
                    path.display()
                )));
            }
        }
    }
    let staging = staging(parent);
    // A leftover of this process id (a crash) is root's and private.
    let _ = fs::remove_dir_all(&staging);
    fs::DirBuilder::new().mode(0o700).create(&staging)?;
    let result = (|| {
        let staged = staging.join(STAGED);
        let listener = std::os::unix::net::UnixListener::bind(&staged)?;
        apply_access(&staged, access)?;
        fs::rename(&staged, path)?;
        let m = fs::symlink_metadata(path)?;
        Ok((
            listener,
            Published {
                path: path.to_owned(),
                dev: m.dev(),
                ino: m.ino(),
            },
        ))
    })();
    let _ = fs::remove_dir(&staging);
    result
}

/// Removes a published socket if its path still holds it (FR-API-1).
pub fn unpublish(p: &Published) {
    if let Ok(m) = fs::symlink_metadata(&p.path)
        && m.file_type().is_socket()
        && m.dev() == p.dev
        && m.ino() == p.ino
    {
        let _ = fs::remove_file(&p.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn access_modes() {
        assert_eq!(Access { gid: Some(5) }.mode(), 0o660);
        assert_eq!(Access { gid: None }.mode(), 0o666);
    }

    #[test]
    fn staging_suffix_bound() {
        assert_eq!(STAGING_SUFFIX_MAX, "/.polywan-staging-4294967295/s".len());
        let parent = Path::new("/run/polywan");
        let staged = staging(parent).join(STAGED);
        assert!(staged.as_os_str().len() <= parent.as_os_str().len() + STAGING_SUFFIX_MAX);
    }
}
