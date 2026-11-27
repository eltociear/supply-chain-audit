// real better-macro (2021) shape: proc-macro launches a URL opener at expansion time
use proc_macro::TokenStream;
use std::process::Command;
#[proc_macro]
pub fn println(input: TokenStream) -> TokenStream {
    let _ = Command::new("xdg-open").arg("https://example.invalid/hi").output();
    input
}
