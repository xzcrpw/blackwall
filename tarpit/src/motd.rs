use rand::Rng;

/// Generate a realistic Ubuntu 24.04 server MOTD banner.
pub fn generate_motd() -> String {
    let mut rng = rand::thread_rng();

    let load: f32 = rng.gen_range(0.1..2.5);
    let procs: u32 = rng.gen_range(150..250);
    let disk_pct: f32 = rng.gen_range(30.0..85.0);
    let mem_pct: u32 = rng.gen_range(25..75);
    let swap_pct: u32 = rng.gen_range(0..10);
    let last_ip = format!(
        "{}.{}.{}.{}",
        rng.gen_range(1..255u8),
        rng.gen_range(0..255u8),
        rng.gen_range(0..255u8),
        rng.gen_range(1..255u8),
    );

    format!(
        r#"
Welcome to Ubuntu 24.04.2 LTS (GNU/Linux 6.5.0-44-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

  System information as of {}

  System load:  {:.2}               Processes:           {}
  Usage of /:   {:.1}% of 49.12GB   Users logged in:     1
  Memory usage: {}%                IPv4 address for eth0: 10.0.2.15
  Swap usage:   {}%

Last login: {} from {}

"#,
        chrono_stub(),
        load,
        procs,
        disk_pct,
        mem_pct,
        swap_pct,
        chrono_stub_recent(),
        last_ip,
    )
}

/// Fake current timestamp using libc (no chrono dep).
fn chrono_stub() -> String {
    format_libc_time(0)
}

fn chrono_stub_recent() -> String {
    // Subtract a random offset (2-6 hours) for "last login"
    let offset_secs = -(rand::Rng::gen_range(&mut rand::thread_rng(), 7200i64..21600));
    format_libc_time(offset_secs)
}

/// Format a timestamp using libc strftime. `offset_secs` is added to current time.
fn format_libc_time(offset_secs: i64) -> String {
    let mut t: nix::libc::time_t = 0;
    // SAFETY: valid pointer
    unsafe { nix::libc::time(&mut t) };
    t += offset_secs;

    let mut tm: nix::libc::tm = unsafe { core::mem::zeroed() };
    // SAFETY: valid pointers
    unsafe { nix::libc::gmtime_r(&t, &mut tm) };

    let mut buf = [0u8; 64];
    let fmt = c"%a %b %e %H:%M:%S %Y";
    // SAFETY: valid buffer, format string, and tm struct
    let len =
        unsafe { nix::libc::strftime(buf.as_mut_ptr() as *mut _, buf.len(), fmt.as_ptr(), &tm) };
    String::from_utf8_lossy(&buf[..len]).to_string()
}
