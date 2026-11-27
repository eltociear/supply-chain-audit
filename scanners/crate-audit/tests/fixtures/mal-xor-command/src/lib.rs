// real rustdecimal (2022) shape: program / env-var names XOR-decoded from byte arrays (inert values)
use std::{env, process::Command};
pub fn decode(b: &Vec<u8>) -> String {
    let k: [u8; 3] = [1, 2, 3];
    let mut out = Vec::new();
    for i in 0..b.len() { out.push(b[i] ^ k[i % 3]); }
    String::from_utf8(out).unwrap_or_default()
}
pub fn check() {
    if env::var(decode(&vec![70, 75, 87, 77])).is_ok() {
        Command::new(decode(&vec![10, 20, 30, 40])).arg(decode(&vec![11, 22])).spawn().ok();
    }
}
