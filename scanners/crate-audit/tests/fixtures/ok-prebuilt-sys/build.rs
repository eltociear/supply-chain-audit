use sha2::{Digest, Sha256};
const URL: &str = "https://github.com/example/releases/download/v1/lib.tgz";
const SHA256: &str = "0000000000000000000000000000000000000000000000000000000000000000";
fn main() {
    let out = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let bytes = ureq::get(URL).call().unwrap().into_reader();
    let mut buf = Vec::new();
    std::io::Read::read_to_end(&mut { bytes }, &mut buf).unwrap();
    assert_eq!(format!("{:x}", Sha256::digest(&buf)), SHA256);
    std::fs::write(out.join("lib.tgz"), &buf).unwrap();
    println!("cargo:rustc-link-search=native={}", out.display());
}
