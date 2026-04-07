//! Minimal base64/base64url codec — no external crates.
//!
//! Used by the A2A firewall (JWT parsing, PoP verification) and
//! the A2A shim (token encoding). A single implementation avoids
//! drift between the three nearly-identical copies that existed before.

/// Standard base64 alphabet lookup table (6-bit value per ASCII char).
const DECODE_TABLE: &[u8; 128] = &{
    let mut t = [255u8; 128];
    let mut i = 0u8;
    while i < 26 {
        t[(b'A' + i) as usize] = i;
        t[(b'a' + i) as usize] = i + 26;
        i += 1;
    }
    let mut i = 0u8;
    while i < 10 {
        t[(b'0' + i) as usize] = i + 52;
        i += 1;
    }
    t[b'+' as usize] = 62;
    t[b'/' as usize] = 63;
    t
};

/// Base64url alphabet for encoding (RFC 4648 §5, no padding).
const ENCODE_TABLE: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Decode a base64url string (no padding required) into bytes.
///
/// Handles the URL-safe alphabet (`-` → `+`, `_` → `/`) and adds
/// padding automatically before delegating to the standard decoder.
pub fn decode_base64url(input: &str) -> Result<Vec<u8>, &'static str> {
    // Add padding if needed
    let padded = match input.len() % 4 {
        2 => format!("{input}=="),
        3 => format!("{input}="),
        0 => input.to_string(),
        _ => return Err("invalid base64url length"),
    };

    // Convert base64url → standard base64
    let standard: String = padded
        .chars()
        .map(|c| match c {
            '-' => '+',
            '_' => '/',
            other => other,
        })
        .collect();

    decode_base64_standard(&standard)
}

/// Decode a standard base64 string (with `=` padding) into bytes.
pub fn decode_base64_standard(input: &str) -> Result<Vec<u8>, &'static str> {
    let bytes = input.as_bytes();
    let len = bytes.len();
    if !len.is_multiple_of(4) {
        return Err("invalid base64 length");
    }

    let mut out = Vec::with_capacity(len / 4 * 3);
    let mut i = 0;
    while i < len {
        let a = bytes[i];
        let b = bytes[i + 1];
        let c = bytes[i + 2];
        let d = bytes[i + 3];

        let va = if a == b'=' { 0 } else if a > 127 { return Err("invalid char") } else { DECODE_TABLE[a as usize] };
        let vb = if b == b'=' { 0 } else if b > 127 { return Err("invalid char") } else { DECODE_TABLE[b as usize] };
        let vc = if c == b'=' { 0 } else if c > 127 { return Err("invalid char") } else { DECODE_TABLE[c as usize] };
        let vd = if d == b'=' { 0 } else if d > 127 { return Err("invalid char") } else { DECODE_TABLE[d as usize] };

        if va == 255 || vb == 255 || vc == 255 || vd == 255 {
            return Err("invalid base64 character");
        }

        let triple = (va as u32) << 18 | (vb as u32) << 12 | (vc as u32) << 6 | (vd as u32);
        out.push((triple >> 16) as u8);
        if c != b'=' {
            out.push((triple >> 8) as u8);
        }
        if d != b'=' {
            out.push(triple as u8);
        }
        i += 4;
    }

    Ok(out)
}

/// Encode bytes to base64url (no padding, RFC 4648 §5).
pub fn encode_base64url(input: &[u8]) -> String {
    let mut out = String::with_capacity((input.len() * 4 / 3) + 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;

        out.push(ENCODE_TABLE[((triple >> 18) & 0x3F) as usize] as char);
        out.push(ENCODE_TABLE[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            out.push(ENCODE_TABLE[((triple >> 6) & 0x3F) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(ENCODE_TABLE[(triple & 0x3F) as usize] as char);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let data = b"Hello, Blackwall!";
        let encoded = encode_base64url(data);
        let decoded = decode_base64url(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn standard_base64_padding() {
        // "Man" → "TWFu"
        assert_eq!(decode_base64_standard("TWFu").unwrap(), b"Man");
        // "Ma" → "TWE="
        assert_eq!(decode_base64_standard("TWE=").unwrap(), b"Ma");
        // "M" → "TQ=="
        assert_eq!(decode_base64_standard("TQ==").unwrap(), b"M");
    }

    #[test]
    fn url_safe_chars() {
        // '+' and '/' in standard → '-' and '_' in url-safe
        let standard = "ab+c/d==";
        let url_safe = "ab-c_d";
        let decode_std = decode_base64_standard(standard).unwrap();
        let decode_url = decode_base64url(url_safe).unwrap();
        assert_eq!(decode_std, decode_url);
    }

    #[test]
    fn invalid_length() {
        assert!(decode_base64url("A").is_err());
    }

    #[test]
    fn invalid_char() {
        assert!(decode_base64_standard("!!!!").is_err());
    }
}
