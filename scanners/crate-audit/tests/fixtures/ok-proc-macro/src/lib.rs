use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, DeriveInput};
#[proc_macro_derive(Hello)]
pub fn derive(input: TokenStream) -> TokenStream {
    let ast = parse_macro_input!(input as DeriveInput);
    let name = &ast.ident;
    let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_default();
    let _ = std::fs::read_to_string(std::path::Path::new(&dir).join("Cargo.toml"));
    quote!(impl #name { pub fn hello() {} }).into()
}
