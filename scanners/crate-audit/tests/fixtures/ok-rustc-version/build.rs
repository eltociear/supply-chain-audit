use std::process::Command;
fn main() {
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".into());
    let out = Command::new(&rustc).arg("--version").output().unwrap();
    let v = String::from_utf8_lossy(&out.stdout);
    if v.contains("nightly") { println!("cargo:rustc-cfg=nightly"); }
    let git = Command::new("git").args(["rev-parse", "HEAD"]).output();
    if let Ok(g) = git { println!("cargo:rustc-env=GIT_HASH={}", String::from_utf8_lossy(&g.stdout).trim()); }
}
