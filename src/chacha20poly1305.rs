use crate::chacha20poly1305_incremental::{AeadUpdate, ChaCha20Poly1305, Nonce, Tag, XChaCha20Poly1305};
use aead::NewAead;
use serde::{Serialize, Deserialize};
use wasm_bindgen::JsValue;
use web_log;

use crate::{OutputStream, ReadStream};

#[derive(Serialize, Deserialize, Debug)]
struct ReadResult {
    done: bool,
    value: Option<Buffer>,
}

#[derive(Serialize, Deserialize, Debug)]
struct Buffer {
    data: Vec<u8>,
}

// Arbitrarily setting chunk size to 256Kb.
// This will add a 16 bytes poly1305 auth tag to each 256Kb block in the encrypted stream. The
// final auth tag is in the last block (which may be less than 256Kb).

pub async fn chacha20poly1305_encrypt_stream(nonce: Vec<u8>, key: Vec<u8>, stream: ReadStream, output: OutputStream)
    -> Result<(), JsValue>
{
    // web_log::println!("encrypt_stream with nonce: {:?}", nonce);

    let mut aead: ChaCha20Poly1305 = ChaCha20Poly1305::new(key[..].into());
    aead.set_nonce(Nonce::from_slice(&nonce[..]));

    // State
    let mut done = false;

    while done == false {
        // Read next chunk from js ReadStream
        // JS error passthrough with ?
        let js_read_chunk = stream.read().await?;

        // Deserialize into ReadResult to get {done, data}
        let mut read_chunk: ReadResult = match js_read_chunk.into_serde() {
            Ok(r) => r,
            Err(e) => Err(format!("WASM js_read_chunk.into_serde error {:?}", e))?
        };

        // Process
        match read_chunk.done {
            true => done = true,  // All data read
            false => {
                // Encrypt data
                match read_chunk.value {
                    Some(mut v) => {
                        aead.encrypt_update(v.data.as_mut_slice());
                        output.write(&v.data[..]).await?;
                    },
                    None => done = true,
                }
            }
        }
    }

    // Empty buffer into the last block
    let r = match aead.encrypt_finalize() {
        Ok(r) => r,
        Err(e) => Err(format!("WASM encrypt_last error : {:?}", e))?
    };
    output.write(&r[..]).await?;

    Ok(())
}

pub async fn chacha20poly1305_decrypt_stream(nonce: Vec<u8>, key: Vec<u8>, stream: ReadStream, output: OutputStream)
    -> Result<(), JsValue>
{
    // web_log::println!("decrypt_stream with nonce: {:?}", nonce);

    let mut aead: ChaCha20Poly1305 = ChaCha20Poly1305::new(key[..].into());
    aead.set_nonce(Nonce::from_slice(&nonce[..]));

    let mut done = false;

    let mut auth_tag = Vec::new();
    while done == false {
        let resultat = stream.read().await?;
        let mut read_result: ReadResult = match resultat.into_serde() {
            Ok(r) => r,
            Err(e) => Err(format!("WASM decrypt js_read_chunk.into_serde error {:?}", e))?
        };

        match read_result.done {
            true => {
                done = true;
            },
            false => {
                match read_result.value {
                    Some(mut v) => {
                        aead.decrypt_update(v.data.as_mut_slice());
                        let last_bytes = &v.data[..v.data.len()-16];
                        auth_tag.extend_from_slice(last_bytes);
                        if auth_tag.len() > 16 {
                            // Cut to last 16 bytes
                            auth_tag = auth_tag.split_off(auth_tag.len() - 16);
                        }
                        output.write(&v.data[..]).await?;
                    },
                    None => done = true,
                }
            }
        }
    }

    // Empty buffer into the last block
    let tag = Tag::from_slice(&auth_tag[..]);
    match aead.decrypt_finalize(tag) {
        Ok(r) => r,
        Err(e) => Err(format!("WASM decrypt_last error : {:?}", e))?
    };
    // output.write(&last_data[..]).await?;

    Ok(())
}
