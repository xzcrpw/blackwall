use anyhow::Result;
use aya::maps::{MapData, RingBuf};
use common::{DpiEvent, EgressEvent, PacketEvent, TlsComponentsEvent};
use crossbeam_queue::SegQueue;
use std::os::fd::AsRawFd;
use std::sync::Arc;
use tokio::io::unix::AsyncFd;

/// Asynchronously consume PacketEvents from the eBPF RingBuf and push them
/// into a lock-free queue for downstream processing.
pub async fn consume_events(
    ring_buf: RingBuf<MapData>,
    event_tx: Arc<SegQueue<PacketEvent>>,
) -> Result<()> {
    let mut ring_buf = ring_buf;
    let async_fd = AsyncFd::new(ring_buf.as_raw_fd())?;

    loop {
        // Wait for readability (epoll-based, no busy-spin)
        let mut guard = async_fd.readable().await?;

        // Drain all available events
        while let Some(event_data) = ring_buf.next() {
            if event_data.len() < core::mem::size_of::<PacketEvent>() {
                continue;
            }
            // SAFETY: PacketEvent is #[repr(C)] with known layout, Pod-safe.
            // eBPF wrote exactly sizeof(PacketEvent) bytes via reserve/submit.
            let event: &PacketEvent = unsafe { &*(event_data.as_ptr() as *const PacketEvent) };
            event_tx.push(*event);
        }

        guard.clear_ready();
    }
}

/// Asynchronously consume TlsComponentsEvents from the eBPF TLS_EVENTS RingBuf
/// and push them into a lock-free queue for JA4 fingerprint assembly.
pub async fn consume_tls_events(
    ring_buf: RingBuf<MapData>,
    tls_tx: Arc<SegQueue<TlsComponentsEvent>>,
) -> Result<()> {
    let mut ring_buf = ring_buf;
    let async_fd = AsyncFd::new(ring_buf.as_raw_fd())?;

    loop {
        let mut guard = async_fd.readable().await?;

        while let Some(event_data) = ring_buf.next() {
            if event_data.len() < core::mem::size_of::<TlsComponentsEvent>() {
                continue;
            }
            // SAFETY: TlsComponentsEvent is #[repr(C)] Pod-safe, written by eBPF reserve/submit.
            let event: &TlsComponentsEvent =
                unsafe { &*(event_data.as_ptr() as *const TlsComponentsEvent) };
            tls_tx.push(*event);
        }

        guard.clear_ready();
    }
}

/// Asynchronously consume EgressEvents from the eBPF EGRESS_EVENTS RingBuf
/// and push them into a lock-free queue for outbound traffic analysis.
pub async fn consume_egress_events(
    ring_buf: RingBuf<MapData>,
    egress_tx: Arc<SegQueue<EgressEvent>>,
) -> Result<()> {
    let mut ring_buf = ring_buf;
    let async_fd = AsyncFd::new(ring_buf.as_raw_fd())?;

    loop {
        let mut guard = async_fd.readable().await?;

        while let Some(event_data) = ring_buf.next() {
            if event_data.len() < core::mem::size_of::<EgressEvent>() {
                continue;
            }
            // SAFETY: EgressEvent is #[repr(C)] Pod-safe, written by eBPF reserve/submit.
            let event: &EgressEvent =
                unsafe { &*(event_data.as_ptr() as *const EgressEvent) };
            egress_tx.push(*event);
        }

        guard.clear_ready();
    }
}

/// Asynchronously consume DpiEvents from the eBPF DPI_EVENTS RingBuf
/// and push them into a lock-free queue for protocol-level analysis.
pub async fn consume_dpi_events(
    ring_buf: RingBuf<MapData>,
    dpi_tx: Arc<SegQueue<DpiEvent>>,
) -> Result<()> {
    let mut ring_buf = ring_buf;
    let async_fd = AsyncFd::new(ring_buf.as_raw_fd())?;

    loop {
        let mut guard = async_fd.readable().await?;

        while let Some(event_data) = ring_buf.next() {
            if event_data.len() < core::mem::size_of::<DpiEvent>() {
                continue;
            }
            // SAFETY: DpiEvent is #[repr(C)] Pod-safe, written by eBPF reserve/submit.
            let event: &DpiEvent =
                unsafe { &*(event_data.as_ptr() as *const DpiEvent) };
            dpi_tx.push(*event);
        }

        guard.clear_ready();
    }
}
