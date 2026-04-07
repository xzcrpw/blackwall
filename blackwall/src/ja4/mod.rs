//! JA4 TLS fingerprinting module.
//!
//! Assembles JA4 fingerprints from raw TLS ClientHello components
//! emitted by the eBPF program. JA4 format:
//!   `t{TLSver}{SNI}{CipherCount}{ExtCount}_{CipherHash}_{ExtHash}`
//!
//! Reference: https://github.com/FoxIO-LLC/ja4

// ARCH: JA4 module is wired into the main event loop via TLS_EVENTS RingBuf.
// eBPF TLS ClientHello parser emits TlsComponentsEvent → JA4 assembly → DB lookup.
pub mod assembler;
pub mod db;
