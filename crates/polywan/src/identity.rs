//! Users and groups of the account databases, through the C library: the
//! hook user (FR-HOOK-3) and the API groups (FR-API-1). Static musl builds
//! read `/etc/passwd` and `/etc/group` and may consult nscd; the
//! documentation requires local accounts (DIST-3).

/// A user's ids, the primary group included.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct User {
    pub uid: u32,
    pub gid: u32,
}

pub fn user(name: &str) -> std::io::Result<Option<User>> {
    let u = nix::unistd::User::from_name(name).map_err(std::io::Error::from)?;
    Ok(u.map(|u| User {
        uid: u.uid.as_raw(),
        gid: u.gid.as_raw(),
    }))
}

pub fn group(name: &str) -> std::io::Result<Option<u32>> {
    let g = nix::unistd::Group::from_name(name).map_err(std::io::Error::from)?;
    Ok(g.map(|g| g.gid.as_raw()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accounts_are_found_by_name() {
        assert_eq!(user("root").unwrap(), Some(User { uid: 0, gid: 0 }));
        assert_eq!(group("root").unwrap(), Some(0));
        assert_eq!(user("polywan-no-such-user").unwrap(), None);
        assert_eq!(group("polywan-no-such-group").unwrap(), None);
    }
}
