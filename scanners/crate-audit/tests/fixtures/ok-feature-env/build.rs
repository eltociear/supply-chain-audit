use std::env;
fn main() {
    for (k, _v) in env::vars() {
        if let Some(f) = k.strip_prefix("CARGO_FEATURE_") {
            println!("cargo:rustc-cfg=feature_{}", f.to_lowercase());
        }
    }
}
