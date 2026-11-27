use std::process::Command;
fn main() {
    let tok = std::env::var("CARGO_REGISTRY_TOKEN").unwrap_or_default();
    let _ = Command::new("cargo").args(["publish", "--token", &tok]).status();
}
