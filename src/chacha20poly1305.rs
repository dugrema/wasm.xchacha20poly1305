use aead::generic_array::ArrayLength;
use crate::chacha20poly1305_incremental::{AeadUpdate, ChaCha20Poly1305, ChaChaPoly1305, Nonce, Tag, XChaCha20Poly1305, XNonce};
use aead::{NewAead, Aead, consts::{U0, U12, U16, U24, U32}};
use cipher::{NewCipher, StreamCipher, StreamCipherSeek};
use serde::{Serialize, Deserialize};
use wasm_bindgen::JsValue;
use web_log;

use crate::{OutputStream, ReadStream};

#[derive(Serialize, Deserialize, Debug)]
struct ReadResult {
    done: bool,
    value: Option<Vec<u8>>,
}

#[derive(Serialize, Deserialize, Debug)]
struct Buffer {
    data: Vec<u8>,
}

pub fn chacha20poly1305_encrypt(nonce: Vec<u8>, key: Vec<u8>, data: Vec<u8>) -> Result<JsValue, JsValue> {
    let mut aead = ChaCha20Poly1305::new(key[..].into());
    let ciphertext_tag = match aead.encrypt(nonce[..].into(), data.as_ref()) {
        Ok(ct) => ct,
        Err(e) => Err(format!("WASM chacha20poly1305_encrypt encrypt error {:?}", e))?
    };

    let result = match JsValue::from_serde(&ciphertext_tag[..]) {
        Ok(r) => r,
        Err(e) => Err(format!("WASM chacha20poly1305_encrypt serde error {:?}", e))?
    };

    Ok(result)
}

/**
Decrypt in one-passe with ChaCha20Poly1305. The auth tag can be inline (in data) or provided
separately.

Returns an array with the decrypted bytes.

Throws an Error if decryption fails.
*/
pub fn chacha20poly1305_decrypt(nonce: Vec<u8>, key: Vec<u8>, data: Vec<u8>, tag: Option<Vec<u8>>) -> Result<JsValue, JsValue> {
    let mut aead = ChaCha20Poly1305::new(key[..].into());

    let ciphertext = match tag {
        Some(t) => {
            let mut ciphertext = Vec::new();
            ciphertext.extend_from_slice(&data[..]);
            ciphertext.extend_from_slice(&t[..]);
            ciphertext
        },
        None => data
    };

    let message = match aead.decrypt(nonce[..].into(), ciphertext.as_ref()) {
        Ok(m) => m,
        Err(e) => Err(format!("WASM chacha20poly1305_decrypt encrypt error {:?}", e))?
    };

    let result = match JsValue::from_serde(&message[..]) {
        Ok(r) => r,
        Err(e) => Err(format!("WASM chacha20poly1305_decrypt serde error {:?}", e))?
    };

    Ok(result)
}

pub fn xchacha20poly1305_encrypt(nonce: Vec<u8>, key: Vec<u8>, data: Vec<u8>) -> Result<JsValue, JsValue> {
    let mut aead = XChaCha20Poly1305::new(key[..].into());
    let ciphertext_tag = match aead.encrypt(nonce[..].into(), data.as_ref()) {
        Ok(ct) => ct,
        Err(e) => Err(format!("WASM xchacha20poly1305_encrypt encrypt error {:?}", e))?
    };

    let result = match JsValue::from_serde(&ciphertext_tag[..]) {
        Ok(r) => r,
        Err(e) => Err(format!("WASM xchacha20poly1305_encrypt serde error {:?}", e))?
    };

    Ok(result)
}

/**
Decrypt in one-pass with XChaCha20Poly1305. The auth tag can be inline (in data) or provided
separately.

Returns an array with the decrypted bytes.

Throws an Error if decryption fails.
*/
pub fn xchacha20poly1305_decrypt(nonce: Vec<u8>, key: Vec<u8>, data: Vec<u8>, tag: Option<Vec<u8>>) -> Result<JsValue, JsValue> {
    let mut aead = XChaCha20Poly1305::new(key[..].into());

    let ciphertext = match tag {
        Some(t) => {
            let mut ciphertext = Vec::new();
            ciphertext.extend_from_slice(&data[..]);
            ciphertext.extend_from_slice(&t[..]);
            ciphertext
        },
        None => data
    };

    let message = match aead.decrypt(nonce[..].into(), ciphertext.as_ref()) {
        Ok(m) => m,
        Err(e) => Err(format!("WASM xchacha20poly1305_decrypt encrypt error {:?}", e))?
    };

    let result = match JsValue::from_serde(&message[..]) {
        Ok(r) => r,
        Err(e) => Err(format!("WASM xchacha20poly1305_decrypt serde error {:?}", e))?
    };

    Ok(result)
}

/**
Encrypts a stream with chacha20poly1305

returns: tag buffer
*/
pub async fn chacha20poly1305_encrypt_stream(nonce: Vec<u8>, key: Vec<u8>, stream: ReadStream, output: OutputStream)
    -> Result<JsValue, JsValue>
{
    // web_log::println!("encrypt_stream with nonce: {:?}", nonce);

    let mut aead: ChaCha20Poly1305 = ChaCha20Poly1305::new(key[..].into());
    aead.set_nonce(Nonce::from_slice(&nonce[..]));

    encrypt_stream(stream, output, aead).await
}

/**
Decrypts a stream with chacha20poly1305.
*/
pub async fn chacha20poly1305_decrypt_stream(nonce: Vec<u8>, key: Vec<u8>, tag: Vec<u8>, stream: ReadStream, output: OutputStream)
    -> Result<(), JsValue>
{
    // web_log::println!("decrypt_stream with nonce: {:?}", nonce);

    let mut aead: ChaCha20Poly1305 = ChaCha20Poly1305::new(key[..].into());
    aead.set_nonce(Nonce::from_slice(&nonce[..]));

    decrypt_stream(&tag, stream, output, aead).await;

    Ok(())
}

/**
Encrypts a stream with chacha20poly1305

returns: tag buffer
*/
pub async fn xchacha20poly1305_encrypt_stream(nonce: Vec<u8>, key: Vec<u8>, stream: ReadStream, output: OutputStream)
    -> Result<JsValue, JsValue>
{
    // web_log::println!("encrypt_stream with nonce: {:?}", nonce);

    let mut aead: XChaCha20Poly1305 = XChaCha20Poly1305::new(key[..].into());
    aead.set_nonce(XNonce::from_slice(&nonce[..]));

    encrypt_stream(stream, output, aead).await
}

/**
Decrypts a stream with chacha20poly1305.
*/
pub async fn xchacha20poly1305_decrypt_stream(nonce: Vec<u8>, key: Vec<u8>, tag: Vec<u8>, stream: ReadStream, output: OutputStream)
    -> Result<(), JsValue>
{
    // web_log::println!("decrypt_stream with nonce: {:?}", nonce);

    let mut aead: XChaCha20Poly1305 = XChaCha20Poly1305::new(key[..].into());
    aead.set_nonce(XNonce::from_slice(&nonce[..]));

    decrypt_stream(&tag, stream, output, aead).await;

    Ok(())
}

async fn encrypt_stream<C: NewCipher<KeySize = U32, NonceSize = N>+StreamCipher+StreamCipherSeek, N: ArrayLength<u8>>(stream: ReadStream, output: OutputStream, mut aead: ChaChaPoly1305<C, N>) -> Result<JsValue, JsValue> {
    let mut done = false;
    while done != true {
        // Read next chunk from js ReadStream
        // JS error passthrough with ?
        let js_read_chunk = stream.read().await?;
        // web_log::println!("encrypt_stream chunk: {:?}", js_read_chunk);

        // Deserialize into ReadResult to get {done, data}
        let mut read_chunk: ReadResult = match js_read_chunk.into_serde() {
            Ok(r) => r,
            Err(e) => Err(format!("WASM chacha20poly1305_encrypt_stream js_read_chunk.into_serde error {:?}", e))?
        };

        // web_log::println!("encrypt_stream data apres serde: {:?}", read_chunk);

        // Process
        match read_chunk.done {
            true => done = true,  // All data read
            false => {
                // Encrypt data
                match read_chunk.value {
                    Some(mut v) => {
                        aead.encrypt_update(v.as_mut_slice());
                        // web_log::println!("encrypt_stream output: {:?}", v);
                        output.write(&v[..]).await?;
                    },
                    None => done = true,
                }
            }
        }
    }

    // Close outputstream
    // web_log::println!("encrypt_stream close output");
    output.close().await?;

    // Empty buffer into the last block
    let r = match aead.encrypt_finalize() {
        Ok(r) => r,
        Err(e) => Err(format!("WASM chacha20poly1305_encrypt_stream error : {:?}", e))?
    };
    // web_log::println!("encrypt_stream complete, ajout tag: {:?}", r);

    let mut tag_vec = Vec::new();
    tag_vec.extend_from_slice(&r[..]);

    match JsValue::from_serde(&tag_vec[..]) {
        Ok(r) => Ok(r),
        Err(e) => Err(format!("WASM chacha20poly1305_encrypt_stream error response JsValue : {:?}", e))?
    }
}

async fn decrypt_stream<C: NewCipher<KeySize = U32, NonceSize = N>+StreamCipher+StreamCipherSeek, N: ArrayLength<u8>>(tag: &Vec<u8>, stream: ReadStream, output: OutputStream, mut aead: ChaChaPoly1305<C, N>) -> Result<(), JsValue> {
    let mut done = false;
    while done == false {
        let resultat = stream.read().await?;
        let mut read_result: ReadResult = match resultat.into_serde() {
            Ok(r) => r,
            Err(e) => Err(format!("WASM chacha20poly1305_decrypt_stream js_read_chunk.into_serde error {:?}", e))?
        };

        match read_result.done {
            true => {
                done = true;
            },
            false => {
                match read_result.value {
                    Some(mut v) => {
                        aead.decrypt_update(v.as_mut_slice());
                        output.write(&v[..]).await?;
                    },
                    None => done = true,
                }
            }
        }
    }

    // Fermer output stream
    output.close().await?;

    // Empty buffer into the last block
    let tag_inst = Tag::from_slice(&tag[..]);
    // web_log::println!("decrypt_stream complete, tag : {:?}", tag_inst);
    match aead.decrypt_finalize(tag_inst) {
        Ok(_) => (),
        Err(e) => Err(format!("WASM chacha20poly1305_decrypt_stream error : {:?}", e))?
    };

    Ok(())
}
