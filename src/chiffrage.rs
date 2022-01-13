use chacha20poly1305::XChaCha20Poly1305;
use chacha20poly1305::aead::NewAead;
use chacha20poly1305::aead::stream::{DecryptorBE32, EncryptorBE32};
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
const CHUNK_SIZE: usize = 256 * 1024;
const CHUNK_TAG_SIZE: usize = CHUNK_SIZE + 16;  // Auth tag Poly1305 = 16 bytes

pub async fn encrypt_stream(nonce: Vec<u8>, key: Vec<u8>, stream: ReadStream, output: OutputStream)
    -> Result<(), JsValue>
{
    // web_log::println!("encrypt_stream with nonce: {:?}", nonce);

    let aead: XChaCha20Poly1305 = XChaCha20Poly1305::new(key[..].into());
    let mut stream_encryptor: EncryptorBE32<XChaCha20Poly1305> = EncryptorBE32::from_aead(aead, nonce[..].into());

    // State
    let mut done = false;
    let mut chunk_buffer = Vec::new();

    while done == false {
        // Read next chunk from js ReadStream
        // JS error passthrough with ?
        let js_read_chunk = stream.read().await?;

        // Deserialize into ReadResult to get {done, data}
        let read_chunk: ReadResult = match js_read_chunk.into_serde() {
            Ok(r) => r,
            Err(e) => Err(format!("WASM js_read_chunk.into_serde error {:?}", e))?
        };

        // Process
        match read_chunk.done {
            true => done = true,  // All data read
            false => {
                // Encrypt data
                match read_chunk.value {
                    Some(v) => encrypt_chunk(&mut stream_encryptor, &output, &mut chunk_buffer, v).await?,
                    None => done = true,
                }
            }
        }
    }

    // Empty buffer into the last block
    let r = match stream_encryptor.encrypt_last(&chunk_buffer[..]) {
        Ok(r) => r,
        Err(e) => Err(format!("WASM encrypt_last error : {:?}", e))?
    };
    output.write(&r[..]).await?;

    Ok(())
}

pub async fn decrypt_stream(nonce: Vec<u8>, key: Vec<u8>, stream: ReadStream, output: OutputStream)
    -> Result<(), JsValue>
{
    // web_log::println!("decrypt_stream with nonce: {:?}", nonce);

    let aead: XChaCha20Poly1305 = XChaCha20Poly1305::new(key[..].into());
    let mut stream_decryptor: DecryptorBE32<XChaCha20Poly1305> = DecryptorBE32::from_aead(aead, nonce[..].into());

    let mut done = false;
    let mut chunk_buffer = Vec::new();
    chunk_buffer.reserve(CHUNK_TAG_SIZE);  // Pre-alloc avec tag

    while done == false {
        let resultat = stream.read().await?;
        let read_result: ReadResult = match resultat.into_serde() {
            Ok(r) => r,
            Err(e) => Err(format!("WASM decrypt js_read_chunk.into_serde error {:?}", e))?
        };

        match read_result.done {
            true => {
                done = true;
            },
            false => {
                match read_result.value {
                    Some(v) => decrypt_chunk(&mut stream_decryptor, &output, & mut chunk_buffer, v).await?,
                    None => done = true,
                }
            }
        }
    }

    // Empty buffer into the last block
    let last_data = match stream_decryptor.decrypt_last(&chunk_buffer[..]) {
        Ok(r) => r,
        Err(e) => Err(format!("WASM decrypt_last error : {:?}", e))?
    };
    output.write(&last_data[..]).await?;

    Ok(())
}

async fn encrypt_chunk(stream_encryptor: &mut EncryptorBE32<XChaCha20Poly1305>, output: &OutputStream, chunk_buffer: &mut Vec<u8>, value: Buffer)
    -> Result<(), String>
{
    // Copy chunk to buffer
    chunk_buffer.extend(value.data);

    while chunk_buffer.len() >= CHUNK_SIZE {
        let mut incomplete_chunk_copy = Vec::new();
        let chunks = chunk_buffer.chunks(CHUNK_SIZE);
        for chunk in chunks {
            if chunk.len() == CHUNK_SIZE {
                let data_chiffre = match stream_encryptor.encrypt_next(&chunk[..]) {
                    Ok(r) => r,
                    Err(e) => Err(format!("WASM Encryption error : {:?}", e))?
                };
                match output.write(&data_chiffre[..]).await {
                    Ok(_) => (),
                    Err(e) => Err(format!("WASM Error writing to output : {:?}", e))?
                }
            } else {
                // Creer nouveau buffer avec chunk
                incomplete_chunk_copy.extend(&chunk[..]);
            }
        }
        chunk_buffer.clear();
        chunk_buffer.extend(&incomplete_chunk_copy[..]);
    }

    Ok(())
}

async fn decrypt_chunk(stream_encryptor: &mut DecryptorBE32<XChaCha20Poly1305>, output: &OutputStream, chunk_buffer: &mut Vec<u8>, value: Buffer)
    -> Result<(), String>
{
    // Copy chunk to buffer
    chunk_buffer.extend(value.data);

    if chunk_buffer.len() >= CHUNK_TAG_SIZE {
        let chunks = chunk_buffer.chunks(CHUNK_TAG_SIZE);
        let mut incomplete_chunk_copy = Vec::new();
        for chunk in chunks {
            if chunk.len() == CHUNK_TAG_SIZE {
                let data_chiffre = match stream_encryptor.decrypt_next(&chunk[..]) {
                    Ok(r) => r,
                    Err(e) => Err(format!("WASM Decryption error : {:?}", e))?
                };
                match output.write(&data_chiffre[..]).await {
                    Ok(_) => (),
                    Err(e) => Err(format!("WASM Error writing to output : {:?}", e))?
                }
            } else {
                // Temporarily copy incomplete chunk, allows for clear()
                incomplete_chunk_copy.extend(&chunk[..]);
            }
        }
        chunk_buffer.clear();

        // Copy incomplete chunk to top of buffer
        chunk_buffer.extend(&incomplete_chunk_copy[..]);
    }

    Ok(())
}
