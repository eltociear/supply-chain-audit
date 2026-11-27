fn main() {
    println!("cargo:rerun-if-changed=src/foo.c");
    let target = std::env::var("TARGET").unwrap();
    let mut b = cc::Build::new();
    b.file("src/foo.c").flag_if_supported("-O2");
    if target.contains("windows") { b.define("WIN", None); }
    b.compile("foo");
    let out = std::env::var("OUT_DIR").unwrap();
    std::fs::write(std::path::Path::new(&out).join("gen.rs"), "pub const X: u8 = 1;").unwrap();
}
