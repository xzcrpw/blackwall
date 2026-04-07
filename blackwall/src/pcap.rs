//! PCAP file writer for forensic packet capture.
//!
//! Writes pcap-format files for flagged IPs. Uses the standard pcap file
//! format (libpcap) without any external dependencies.

#![allow(dead_code)]

use anyhow::{Context, Result};
use std::collections::HashSet;
use std::io::Write;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::Mutex;

/// PCAP global header magic number (microsecond resolution).
const PCAP_MAGIC: u32 = 0xa1b2c3d4;
/// PCAP version 2.4.
const PCAP_VERSION_MAJOR: u16 = 2;
const PCAP_VERSION_MINOR: u16 = 4;
/// Maximum bytes to capture per packet.
const SNAP_LEN: u32 = 65535;
/// Link type: raw IPv4 (DLT_RAW = 228). Alternative: Ethernet = 1.
const LINK_TYPE_RAW: u32 = 228;

/// Maximum PCAP file size before rotation (100 MB).
const MAX_FILE_SIZE: u64 = 100 * 1024 * 1024;
/// Maximum number of rotated files to keep.
const MAX_ROTATED_FILES: usize = 10;

/// Manages PCAP capture for flagged IPs.
pub struct PcapWriter {
    /// Directory to write pcap files.
    output_dir: PathBuf,
    /// Set of IPs currently flagged for capture.
    flagged_ips: Mutex<HashSet<u32>>,
    /// Currently open pcap file (if any).
    file: Mutex<Option<PcapFile>>,
}

struct PcapFile {
    writer: std::io::BufWriter<std::fs::File>,
    path: PathBuf,
    bytes_written: u64,
}

impl PcapWriter {
    /// Create a new PCAP writer with the given output directory.
    pub fn new(output_dir: PathBuf) -> Result<Self> {
        std::fs::create_dir_all(&output_dir)
            .with_context(|| format!("failed to create pcap dir: {}", output_dir.display()))?;
        Ok(Self {
            output_dir,
            flagged_ips: Mutex::new(HashSet::new()),
            file: Mutex::new(None),
        })
    }

    /// Flag an IP for packet capture.
    pub fn flag_ip(&self, ip: Ipv4Addr) {
        let raw = u32::from(ip);
        let mut ips = self.flagged_ips.lock().expect("flagged_ips lock");
        if ips.insert(raw) {
            tracing::info!(%ip, "PCAP capture enabled for IP");
        }
    }

    /// Remove an IP from capture.
    #[allow(dead_code)]
    pub fn unflag_ip(&self, ip: Ipv4Addr) {
        let raw = u32::from(ip);
        let mut ips = self.flagged_ips.lock().expect("flagged_ips lock");
        if ips.remove(&raw) {
            tracing::info!(%ip, "PCAP capture disabled for IP");
        }
    }

    /// Check if an IP is flagged for capture.
    pub fn is_flagged(&self, src_ip: u32) -> bool {
        let ips = self.flagged_ips.lock().expect("flagged_ips lock");
        ips.contains(&src_ip)
    }

    /// Write a raw IP packet to the pcap file (if the IP is flagged).
    pub fn write_packet(&self, src_ip: u32, dst_ip: u32, data: &[u8]) -> Result<()> {
        // Check if either endpoint is flagged
        let ips = self.flagged_ips.lock().expect("flagged_ips lock");
        if !ips.contains(&src_ip) && !ips.contains(&dst_ip) {
            return Ok(());
        }
        drop(ips); // Release lock before I/O

        let mut file_guard = self.file.lock().expect("pcap file lock");

        // Open file if needed, or rotate if too large
        let pcap = match file_guard.as_mut() {
            Some(f) if f.bytes_written < MAX_FILE_SIZE => f,
            Some(_) => {
                // Rotate
                let old = file_guard.take().expect("just checked Some");
                drop(old);
                self.rotate_files()?;
                let new_file = self.open_new_file()?;
                *file_guard = Some(new_file);
                file_guard.as_mut().expect("just created")
            }
            None => {
                let new_file = self.open_new_file()?;
                *file_guard = Some(new_file);
                file_guard.as_mut().expect("just created")
            }
        };

        // Write pcap packet record
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let ts_sec = ts.as_secs() as u32;
        let ts_usec = ts.subsec_micros();
        let cap_len = data.len().min(SNAP_LEN as usize) as u32;

        // Packet header: ts_sec(4) + ts_usec(4) + cap_len(4) + orig_len(4)
        pcap.writer.write_all(&ts_sec.to_le_bytes())?;
        pcap.writer.write_all(&ts_usec.to_le_bytes())?;
        pcap.writer.write_all(&cap_len.to_le_bytes())?;
        pcap.writer.write_all(&(data.len() as u32).to_le_bytes())?;
        pcap.writer.write_all(&data[..cap_len as usize])?;
        pcap.writer.flush()?;

        pcap.bytes_written += 16 + cap_len as u64;

        Ok(())
    }

    /// Open a new pcap file with a global header.
    fn open_new_file(&self) -> Result<PcapFile> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let path = self.output_dir.join(format!("capture_{}.pcap", timestamp));

        let file = std::fs::File::create(&path)
            .with_context(|| format!("failed to create pcap: {}", path.display()))?;
        let mut writer = std::io::BufWriter::new(file);

        // Write pcap global header
        writer.write_all(&PCAP_MAGIC.to_le_bytes())?;
        writer.write_all(&PCAP_VERSION_MAJOR.to_le_bytes())?;
        writer.write_all(&PCAP_VERSION_MINOR.to_le_bytes())?;
        writer.write_all(&0i32.to_le_bytes())?; // thiszone
        writer.write_all(&0u32.to_le_bytes())?; // sigfigs
        writer.write_all(&SNAP_LEN.to_le_bytes())?;
        writer.write_all(&LINK_TYPE_RAW.to_le_bytes())?;
        writer.flush()?;

        tracing::info!(path = %path.display(), "opened new PCAP file");

        Ok(PcapFile {
            writer,
            path,
            bytes_written: 24, // Global header size
        })
    }

    /// Rotate pcap files: remove oldest if exceeding MAX_ROTATED_FILES.
    fn rotate_files(&self) -> Result<()> {
        let mut entries: Vec<PathBuf> = std::fs::read_dir(&self.output_dir)?
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.path()
                    .extension()
                    .map(|ext| ext == "pcap" || ext == "gz")
                    .unwrap_or(false)
            })
            .map(|e| e.path())
            .collect();

        entries.sort();

        while entries.len() >= MAX_ROTATED_FILES {
            if let Some(oldest) = entries.first() {
                tracing::info!(path = %oldest.display(), "rotating old PCAP file");
                std::fs::remove_file(oldest)?;
                entries.remove(0);
            }
        }

        Ok(())
    }

    /// Compress a pcap file using gzip. Returns path to compressed file.
    pub fn compress_file(path: &std::path::Path) -> Result<PathBuf> {
        use std::process::Command;
        let output = Command::new("gzip")
            .arg("-f") // Force overwrite
            .arg(path.as_os_str())
            .output()
            .with_context(|| format!("failed to run gzip on {}", path.display()))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("gzip failed: {}", stderr);
        }

        let gz_path = path.with_extension("pcap.gz");
        Ok(gz_path)
    }

    /// Get the number of flagged IPs.
    #[allow(dead_code)]
    pub fn flagged_count(&self) -> usize {
        self.flagged_ips.lock().expect("flagged_ips lock").len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pcap_global_header_size() {
        // PCAP global header is exactly 24 bytes
        let size = 4 + 2 + 2 + 4 + 4 + 4 + 4; // magic + ver_maj + ver_min + tz + sigfigs + snaplen + link
        assert_eq!(size, 24);
    }

    #[test]
    fn flag_and_check_ip() {
        let dir = std::env::temp_dir().join("blackwall_pcap_test");
        let writer = PcapWriter::new(dir.clone()).unwrap();

        let ip = Ipv4Addr::new(192, 168, 1, 1);
        assert!(!writer.is_flagged(u32::from(ip)));

        writer.flag_ip(ip);
        assert!(writer.is_flagged(u32::from(ip)));

        writer.unflag_ip(ip);
        assert!(!writer.is_flagged(u32::from(ip)));

        // Cleanup
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn write_and_verify_pcap() {
        let dir = std::env::temp_dir().join("blackwall_pcap_write_test");
        let writer = PcapWriter::new(dir.clone()).unwrap();

        let src_ip = Ipv4Addr::new(10, 0, 0, 1);
        writer.flag_ip(src_ip);

        // Fake IP packet (just some bytes)
        let packet = [0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00,
                      0x40, 0x06, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01,
                      0xc0, 0xa8, 0x01, 0x01];

        writer.write_packet(u32::from(src_ip), u32::from(Ipv4Addr::new(192, 168, 1, 1)), &packet).unwrap();

        // Verify file was created
        let files: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().map(|ext| ext == "pcap").unwrap_or(false))
            .collect();
        assert_eq!(files.len(), 1);

        // Verify file starts with pcap magic
        let content = std::fs::read(files[0].path()).unwrap();
        assert!(content.len() >= 24); // At least global header
        let magic = u32::from_le_bytes([content[0], content[1], content[2], content[3]]);
        assert_eq!(magic, PCAP_MAGIC);

        // Cleanup
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn unflagged_ip_not_captured() {
        let dir = std::env::temp_dir().join("blackwall_pcap_skip_test");
        let writer = PcapWriter::new(dir.clone()).unwrap();

        let packet = [0x45, 0x00];
        // No IPs flagged — should be a no-op
        writer.write_packet(0x0a000001, 0xc0a80101, &packet).unwrap();

        let files: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().map(|ext| ext == "pcap").unwrap_or(false))
            .collect();
        assert!(files.is_empty());

        // Cleanup
        let _ = std::fs::remove_dir_all(dir);
    }
}
