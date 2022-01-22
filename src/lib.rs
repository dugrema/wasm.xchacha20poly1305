// Refs
// https://developer.mozilla.org/en-US/docs/WebAssembly/Rust_to_wasm
// https://kerkour.com/rust-file-encryption/

// mod chiffrage;
mod chacha20poly1305_incremental;
mod chacha20poly1305;

use wasm_bindgen::prelude::*;
// use crate::chiffrage::{encrypt_stream, decrypt_stream};
use crate::chacha20poly1305::{
    xchacha20poly1305_encrypt_stream as _xchacha20poly1305_encrypt_stream,
    xchacha20poly1305_decrypt_stream as _xchacha20poly1305_decrypt_stream,
    chacha20poly1305_encrypt_stream as _chacha20poly1305_encrypt_stream,
    chacha20poly1305_decrypt_stream as _chacha20poly1305_decrypt_stream,
};

// When the `wee_alloc` feature is enabled, use `wee_alloc` as the global allocator.
// #[cfg(feature = "wee_alloc")]
// #[global_allocator]
// static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[wasm_bindgen]
extern "C" {
    pub type ReadStream;

    #[wasm_bindgen(catch, method)]
    async fn read(this: &ReadStream) -> Result<JsValue, JsValue>;
}

#[wasm_bindgen]
extern "C" {
    pub type OutputStream;

    #[wasm_bindgen(catch, method)]
    async fn write(this: &OutputStream, output: &[u8]) -> Result<JsValue, JsValue>;
}

#[wasm_bindgen(catch)]
pub async fn xchacha20poly1305_encrypt_stream(nonce: Vec<u8>, key: Vec<u8>, stream: ReadStream, output: OutputStream) -> Result<JsValue, JsValue>{
    _xchacha20poly1305_encrypt_stream(nonce, key, stream, output).await
}

#[wasm_bindgen(catch)]
pub async fn xchacha20poly1305_decrypt_stream(nonce: Vec<u8>, key: Vec<u8>, tag: Vec<u8>, stream: ReadStream, output: OutputStream) -> Result<(), JsValue>{
    _xchacha20poly1305_decrypt_stream(nonce, key, tag, stream, output).await
}

#[wasm_bindgen(catch)]
pub async fn chacha20poly1305_encrypt_stream(nonce: Vec<u8>, key: Vec<u8>, stream: ReadStream, output: OutputStream) -> Result<JsValue, JsValue>{
    _chacha20poly1305_encrypt_stream(nonce, key, stream, output).await
}

#[wasm_bindgen(catch)]
pub async fn chacha20poly1305_decrypt_stream(nonce: Vec<u8>, key: Vec<u8>, tag: Vec<u8>, stream: ReadStream, output: OutputStream) -> Result<(), JsValue>{
    _chacha20poly1305_decrypt_stream(nonce, key, tag, stream, output).await
}