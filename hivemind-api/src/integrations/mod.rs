//! SIEM/SOAR integration format exporters.
//!
//! Converts verified IoCs to industry-standard SIEM ingestion formats:
//!
//! - `splunk` — Splunk HTTP Event Collector (HEC) JSON format
//! - `qradar` — IBM QRadar LEEF (Log Event Extended Format)
//! - `cef`    — ArcSight Common Event Format (CEF)

pub mod cef;
pub mod qradar;
pub mod splunk;
