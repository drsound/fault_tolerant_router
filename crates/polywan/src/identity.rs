//! Users and groups of the local account databases (`/etc/passwd`,
//! `/etc/group`): the hook user (FR-HOOK-3) and the API groups (FR-API-1).
//! Static musl binaries have no NSS modules, so these files are what a
//! lookup reads anyway; accounts known only to LDAP or SSSD are not found.

use std::path::Path;

/// A user's ids, the primary group included.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct User {
    pub uid: u32,
    pub gid: u32,
}

pub fn user(name: &str) -> std::io::Result<Option<User>> {
    user_in(Path::new("/etc/passwd"), name)
}

pub fn group(name: &str) -> std::io::Result<Option<u32>> {
    group_in(Path::new("/etc/group"), name)
}

fn user_in(file: &Path, name: &str) -> std::io::Result<Option<User>> {
    // name:password:uid:gid:gecos:home:shell
    Ok(find(&std::fs::read_to_string(file)?, name).and_then(|f| {
        Some(User {
            uid: f.get(2)?.parse().ok()?,
            gid: f.get(3)?.parse().ok()?,
        })
    }))
}

fn group_in(file: &Path, name: &str) -> std::io::Result<Option<u32>> {
    // name:password:gid:members
    Ok(find(&std::fs::read_to_string(file)?, name).and_then(|f| f.get(2)?.parse().ok()))
}

/// The fields of the first entry named `name`, as the C library reads the
/// files (the first match wins; `+`/`-` compatibility entries never match a
/// valid name).
fn find<'a>(text: &'a str, name: &str) -> Option<Vec<&'a str>> {
    text.lines()
        .map(|l| l.split(':').collect::<Vec<_>>())
        .find(|f| f.first() == Some(&name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entries_are_found_by_name() {
        let dir = std::env::temp_dir().join(format!("polywan-identity-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let passwd = dir.join("passwd");
        std::fs::write(
            &passwd,
            "root:x:0:0:root:/root:/bin/sh\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\nbad:x:z:1::/:/bin/sh\n",
        )
        .unwrap();
        let group = dir.join("group");
        std::fs::write(&group, "root:x:0:\npolywan:x:997:alice,bob\npolywan:x:5:\n").unwrap();
        assert_eq!(
            user_in(&passwd, "nobody").unwrap(),
            Some(User { uid: 65534, gid: 65534 })
        );
        assert_eq!(user_in(&passwd, "nob").unwrap(), None);
        assert_eq!(user_in(&passwd, "bad").unwrap(), None);
        assert_eq!(group_in(&group, "polywan").unwrap(), Some(997));
        assert_eq!(group_in(&group, "staff").unwrap(), None);
        assert!(user_in(&dir.join("missing"), "root").is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
