use std::process::Command;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    match args.get(1).map(|s| s.as_str()) {
        Some("build-ebpf") => build_ebpf(),
        Some(cmd) => {
            eprintln!("Unknown command: {cmd}");
            std::process::exit(1);
        }
        None => {
            eprintln!("Usage: cargo xtask <command>");
            eprintln!("Commands:");
            eprintln!("  build-ebpf    Build eBPF programs");
            std::process::exit(1);
        }
    }
}

fn build_ebpf() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")
        .expect("CARGO_MANIFEST_DIR not set");
    let workspace_root = std::path::Path::new(&manifest_dir)
        .parent()
        .expect("cannot find workspace root");
    let ebpf_dir = workspace_root.join("blackwall-ebpf");

    let status = Command::new("cargo")
        .current_dir(&ebpf_dir)
        .args([
            "+nightly",
            "build",
            "--release",
            "--target",
            "bpfel-unknown-none",
            "-Z",
            "build-std=core",
        ])
        .status()
        .expect("failed to execute cargo build for eBPF");

    if !status.success() {
        std::process::exit(status.code().unwrap_or(1));
    }
}
