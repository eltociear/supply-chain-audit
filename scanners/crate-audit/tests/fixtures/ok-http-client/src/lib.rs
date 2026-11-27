// runtime networking + config: ordinary for an API client
pub fn get(url: &str) -> String {
    let token = std::env::var("API_TOKEN").unwrap_or_default();
    reqwest::blocking::Client::new().get(url).bearer_auth(token).send().unwrap().text().unwrap()
}
pub fn home_cfg() -> std::path::PathBuf { dirs::home_dir().unwrap().join(".config/myapp") }
