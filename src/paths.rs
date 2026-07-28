//! Filesystem location and path-resolution primitives.
//!
//! A leaf module: it depends on nothing else in the crate. Both the §3 invariant
//! gate (which resolves argument paths and protects the home directory) and the
//! ledger (which writes inside the home directory) build on it, so neither has to
//! reach into the other for a location concern. The Phase 1 normalization
//! pipeline (§7.4) will reuse `resolve_path` too.

use std::path::{Component, Path, PathBuf};

/// The Penstock home directory: `PENSTOCK_HOME`, else `~/.penstock`. Holds
/// config, ledger, and pin store. The invariant gate protects this location and
/// the ledger writes inside it, so the ledger is covered by I1 for free — see the
/// I-5 test in `ledger`.
pub fn penstock_home() -> PathBuf {
    match std::env::var_os("PENSTOCK_HOME") {
        Some(value) => expand_tilde(&value.to_string_lossy()),
        None => home_dir().unwrap_or_default().join(".penstock"),
    }
}

/// Resolve a raw argument string to an absolute, symlink- and `..`-resolved path.
///
/// Expands a leading `~`, then resolves the same way as [`resolve_path`].
pub fn resolve_target(raw: &str) -> PathBuf {
    resolve_path(&expand_tilde(raw))
}

/// Resolve a path to an absolute, symlink- and `..`-resolved form.
///
/// Canonicalizing the *deepest existing ancestor* resolves symlinks and `..` for
/// the real portion of the path (this is what follows a symlinked directory
/// component into a protected directory); the non-existent tail is then
/// normalized lexically. This is the correct answer for a target that does not
/// exist yet — plain `fs::canonicalize` fails outright on such a path.
pub fn resolve_path(input: &Path) -> PathBuf {
    let absolute = if input.is_absolute() {
        input.to_path_buf()
    } else {
        match std::env::current_dir() {
            Ok(cwd) => cwd.join(input),
            Err(_) => input.to_path_buf(),
        }
    };

    let components: Vec<Component> = absolute.components().collect();

    // Find the deepest existing prefix.
    let mut existing_len = components.len();
    while existing_len > 0 && !join_components(&components[..existing_len]).exists() {
        existing_len -= 1;
    }

    let base = join_components(&components[..existing_len]);
    let mut resolved = std::fs::canonicalize(&base).unwrap_or(base);

    // Normalize the non-existent tail lexically. Nothing here exists, so there
    // are no symlinks to follow; `..` is a pure pop against the canonical base.
    for component in &components[existing_len..] {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                resolved.pop();
            }
            Component::Normal(name) => resolved.push(name),
            Component::RootDir => resolved.push(std::path::MAIN_SEPARATOR_STR),
            Component::Prefix(prefix) => resolved.push(prefix.as_os_str()),
        }
    }
    resolved
}

/// Rebuild a path from components. `RootDir` re-anchors at the filesystem root.
fn join_components(components: &[Component]) -> PathBuf {
    let mut path = PathBuf::new();
    for component in components {
        path.push(component.as_os_str());
    }
    path
}

/// Expand a leading `~` or `~/` to the user's home. `~user` is not handled.
fn expand_tilde(raw: &str) -> PathBuf {
    if raw == "~" {
        return home_dir().unwrap_or_else(|| PathBuf::from(raw));
    }
    if let Some(rest) = raw.strip_prefix("~/") {
        return home_dir()
            .map(|home| home.join(rest))
            .unwrap_or_else(|| PathBuf::from(raw));
    }
    PathBuf::from(raw)
}

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_existing_path_to_canonical_form() {
        let dir = tempfile::tempdir().unwrap();
        let canonical = std::fs::canonicalize(dir.path()).unwrap();
        assert_eq!(resolve_path(dir.path()), canonical);
    }

    #[test]
    fn resolves_nonexistent_leaf_under_existing_parent() {
        // The parent exists; the leaf does not. Resolution must still land the
        // leaf under the canonical parent (the write-into-a-new-file case).
        let dir = tempfile::tempdir().unwrap();
        let canonical = std::fs::canonicalize(dir.path()).unwrap();
        assert_eq!(
            resolve_path(&dir.path().join("nope")),
            canonical.join("nope")
        );
    }

    #[test]
    fn collapses_dotdot_against_canonical_base() {
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("sub");
        std::fs::create_dir(&sub).unwrap();
        let canonical = std::fs::canonicalize(dir.path()).unwrap();
        assert_eq!(
            resolve_path(&sub.join("..").join("leaf")),
            canonical.join("leaf")
        );
    }

    #[test]
    fn expands_leading_tilde_only() {
        let home = home_dir().unwrap_or_else(|| PathBuf::from("~"));
        assert_eq!(expand_tilde("~/x"), home.join("x"));
        // A tilde not at the start is a literal path component.
        assert_eq!(expand_tilde("/a/~/b"), PathBuf::from("/a/~/b"));
    }
}
