//! Persistent node identity — load or generate Ed25519 keypair.
//!
//! On first launch the keypair is generated and saved to disk.
//! Subsequent launches reuse the same identity so the PeerId is
//! stable across restarts and reputation persists in the mesh.
//!
//! SECURITY: The key file is created with mode 0600 (owner-only).
//! If the permissions are wrong at load time we refuse to start
//! rather than risk using a compromised key.

use anyhow::Context;
use libp2p::identity::Keypair;
use std::fs;
use std::path::{Path, PathBuf};
use tracing::info;
#[cfg(not(unix))]
use tracing::warn;

/// Default directory for Blackwall identity and state.
const DEFAULT_DATA_DIR: &str = ".blackwall";
/// Filename for the Ed25519 secret key (PKCS#8 DER).
const IDENTITY_FILENAME: &str = "identity.key";
/// Expected Unix permissions (read/write owner only).
#[cfg(unix)]
const REQUIRED_MODE: u32 = 0o600;

/// Resolve the identity key path.
///
/// Priority:
/// 1. Explicit path from config (`identity_key_path`)
/// 2. `/etc/blackwall/identity.key` when running as root
/// 3. `~/.blackwall/identity.key` otherwise
pub fn resolve_key_path(explicit: Option<&str>) -> anyhow::Result<PathBuf> {
    if let Some(p) = explicit {
        return Ok(PathBuf::from(p));
    }

    // Running as root → system-wide path
    #[cfg(unix)]
    if nix::unistd::geteuid().is_root() {
        return Ok(PathBuf::from("/etc/blackwall").join(IDENTITY_FILENAME));
    }

    // Regular user → home dir
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .context("Cannot determine home directory (neither HOME nor USERPROFILE set)")?;
    Ok(PathBuf::from(home).join(DEFAULT_DATA_DIR).join(IDENTITY_FILENAME))
}

/// Load an existing keypair or generate a new one and persist it.
pub fn load_or_generate(key_path: &Path) -> anyhow::Result<Keypair> {
    if key_path.exists() {
        load_keypair(key_path)
    } else {
        generate_and_save(key_path)
    }
}

/// Load keypair from disk, verifying file permissions first.
fn load_keypair(path: &Path) -> anyhow::Result<Keypair> {
    verify_permissions(path)?;

    let der = fs::read(path)
        .with_context(|| format!("Failed to read identity key: {}", path.display()))?;

    let keypair = Keypair::from_protobuf_encoding(&der)
        .context("Failed to decode identity key (corrupt or wrong format?)")?;

    info!(path = %path.display(), "Loaded persistent identity");
    Ok(keypair)
}

/// Generate a fresh Ed25519 keypair, create parent dirs, save with 0600.
fn generate_and_save(path: &Path) -> anyhow::Result<Keypair> {
    let keypair = Keypair::generate_ed25519();

    // Create parent directory if missing
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Cannot create directory: {}", parent.display()))?;
        // SECURITY: restrict directory to owner-only on Unix
        #[cfg(unix)]
        set_permissions(parent, 0o700)?;
    }

    // Serialize to protobuf (libp2p's canonical format)
    let encoded = keypair
        .to_protobuf_encoding()
        .context("Failed to encode keypair")?;

    fs::write(path, &encoded)
        .with_context(|| format!("Failed to write identity key: {}", path.display()))?;

    // SECURITY: set 0600 immediately after write
    #[cfg(unix)]
    set_permissions(path, REQUIRED_MODE)?;

    info!(
        path = %path.display(),
        "Generated new persistent identity (saved to disk)"
    );
    Ok(keypair)
}

/// Verify that the key file has strict permissions (Unix only).
#[cfg(unix)]
fn verify_permissions(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let meta = fs::metadata(path)
        .with_context(|| format!("Cannot stat identity key: {}", path.display()))?;
    let mode = meta.permissions().mode() & 0o777;
    if mode != REQUIRED_MODE {
        anyhow::bail!(
            "Identity key {} has insecure permissions {:04o} (expected {:04o}). \
             Fix with: chmod 600 {}",
            path.display(),
            mode,
            REQUIRED_MODE,
            path.display(),
        );
    }
    Ok(())
}

/// No-op permission check on non-Unix platforms.
#[cfg(not(unix))]
fn verify_permissions(_path: &Path) -> anyhow::Result<()> {
    warn!("File permission check skipped (non-Unix platform)");
    Ok(())
}

/// Set file/dir permissions (Unix only).
#[cfg(unix)]
fn set_permissions(path: &Path, mode: u32) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::Permissions::from_mode(mode);
    fs::set_permissions(path, perms)
        .with_context(|| format!("Cannot set permissions {:04o} on {}", mode, path.display()))?;
    Ok(())
}
