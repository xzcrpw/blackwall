/// Sanitize attacker input before sending to LLM.
///
/// Strips null bytes, control characters (except newline), and truncates
/// to a safe maximum length to prevent prompt injection amplification.
const MAX_INPUT_LEN: usize = 512;

/// Clean raw bytes from attacker into a safe UTF-8 string.
pub fn clean_input(raw: &[u8]) -> String {
    let s = String::from_utf8_lossy(raw);
    let cleaned: String = s
        .chars()
        .filter(|c| !c.is_control() || *c == '\n')
        .take(MAX_INPUT_LEN)
        .collect();
    cleaned.trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_null_bytes() {
        let input = b"ls\x00 -la\x00";
        let result = clean_input(input);
        assert_eq!(result, "ls -la");
    }

    #[test]
    fn strips_control_chars() {
        let input = b"cat \x07\x08/etc/passwd";
        let result = clean_input(input);
        assert_eq!(result, "cat /etc/passwd");
    }

    #[test]
    fn preserves_newlines() {
        let input = b"echo hello\necho world";
        let result = clean_input(input);
        assert_eq!(result, "echo hello\necho world");
    }

    #[test]
    fn truncates_long_input() {
        let long = vec![b'A'; 1024];
        let result = clean_input(&long);
        assert_eq!(result.len(), MAX_INPUT_LEN);
    }

    #[test]
    fn handles_invalid_utf8() {
        let input = b"hello\xff\xfeworld";
        let result = clean_input(input);
        assert!(result.contains("hello"));
        assert!(result.contains("world"));
    }

    #[test]
    fn trims_whitespace() {
        let input = b"  ls -la  \n  ";
        let result = clean_input(input);
        assert_eq!(result, "ls -la");
    }

    #[test]
    fn empty_input() {
        let result = clean_input(b"");
        assert_eq!(result, "");
    }
}
