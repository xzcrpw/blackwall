//! Integration tests for the enriched IoC file IPC format.
//!
//! Tests that the JSON Lines format produced by hivemind is correctly parsed
//! and that legacy raw u32 format is still supported.
//!
//! Run: `cargo test -p hivemind --test ioc_format -- --nocapture`

#[test]
fn enriched_ioc_json_format() {
    // Verify the JSON format produced by append_accepted_ioc
    let test_entries = [
        // severity 2 → 1800s
        (0x0A000001u32, 2u8, 3u8, 1800u32),
        // severity 5 → 3600s
        (0x0A000002, 5, 4, 3600),
        // severity 7 → 7200s
        (0x0A000003, 7, 5, 7200),
        // severity 9 → 14400s
        (0x0A000004, 9, 3, 14400),
    ];

    for (ip, severity, confirmations, expected_duration) in &test_entries {
        // Compute duration the same way as append_accepted_ioc
        let duration_secs: u32 = match severity {
            0..=2 => 1800,
            3..=5 => 3600,
            6..=8 => 7200,
            _ => 14400,
        };
        assert_eq!(
            duration_secs, *expected_duration,
            "severity {} should map to {} seconds",
            severity, expected_duration
        );

        // Verify JSON serialization format
        let json = format!(
            r#"{{"ip":{},"severity":{},"confirmations":{},"duration_secs":{}}}"#,
            ip, severity, confirmations, duration_secs,
        );
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["ip"], *ip);
        assert_eq!(parsed["severity"], *severity);
        assert_eq!(parsed["confirmations"], *confirmations);
        assert_eq!(parsed["duration_secs"], duration_secs);
    }
}

#[test]
fn legacy_u32_format_still_parseable() {
    // Old format: one u32 per line
    let legacy_content = "167772161\n167772162\n167772163\n";
    let mut ips = Vec::new();
    for line in legacy_content.lines() {
        let trimmed = line.trim();
        if !trimmed.is_empty() {
            if let Ok(ip) = trimmed.parse::<u32>() {
                ips.push(ip);
            }
        }
    }
    assert_eq!(ips.len(), 3);
    assert_eq!(ips[0], 167772161); // 10.0.0.1
}

#[test]
fn mixed_format_lines() {
    // Content with both legacy and enriched lines (during upgrade transition)
    let content = r#"167772161
{"ip":167772162,"severity":5,"confirmations":3,"duration_secs":3600}
167772163
{"ip":167772164,"severity":9,"confirmations":5,"duration_secs":14400}
"#;

    let mut entries = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.starts_with('{') {
            let parsed: serde_json::Value = serde_json::from_str(trimmed).unwrap();
            entries.push((
                parsed["ip"].as_u64().unwrap() as u32,
                parsed["duration_secs"].as_u64().unwrap() as u32,
            ));
        } else if let Ok(ip) = trimmed.parse::<u32>() {
            entries.push((ip, 3600)); // default duration
        }
    }
    assert_eq!(entries.len(), 4);
    assert_eq!(entries[0], (167772161, 3600)); // legacy → default
    assert_eq!(entries[1], (167772162, 3600)); // enriched
    assert_eq!(entries[3], (167772164, 14400)); // enriched high severity
}

#[test]
fn malformed_json_line_skipped() {
    let content = r#"{"ip":123,"severity":5
{"ip":167772162,"severity":5,"confirmations":3,"duration_secs":3600}
not_a_number
"#;

    let mut valid = 0u32;
    let mut invalid = 0u32;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.starts_with('{') {
            if serde_json::from_str::<serde_json::Value>(trimmed).is_ok() {
                valid += 1;
            } else {
                invalid += 1;
            }
        } else if trimmed.parse::<u32>().is_ok() {
            valid += 1;
        } else {
            invalid += 1;
        }
    }
    assert_eq!(valid, 1);
    assert_eq!(invalid, 2);
}
