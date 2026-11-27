// real sha-rust / microsoftsystem64 (2025-26) shape: collector URL stored base64-encoded
use base64::{engine::general_purpose, Engine as _};
const C2: &str = "aHR0cHM6Ly9jb2xsZWN0LmV4YW1wbGUuaW52YWxpZC9hcGk="; // https://collect.example.invalid/api
pub fn url() -> String { String::from_utf8(general_purpose::STANDARD.decode(C2).unwrap()).unwrap() }
