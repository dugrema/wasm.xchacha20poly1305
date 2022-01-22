# wasm.xchacha20poly1305
WASM version of ChaCha20Poly1305 and XChaCha20Poly1305 in rust

## Description

This is a WASM wrapper around some operations in the Rust crate chacha20poly1305. 

The "one-pass" encrypt/decrypt functions use the original algorithm from the Rust crate chacha20poly1305.

I have modified the ciphers to support incremental processing (calling ..._update() then ..._finalize()) to 
support encrypting large files that don't fit in memory. These are the _stream functions available in this wrapper.
This incurs a performance cost when compared to the one-pass version but should allow processing files up to 256 GB.

## References

Github : https://github.com/dugrema/wasm.xchacha20poly1305

* https://docs.rs/chacha20poly1305/latest/chacha20poly1305/index.html
* https://koala42.com/using-webassembly-in-your-reactjs-app/

# How to install

Add to your project, for example using npm:

`npm i @dugrema/wasm-xchacha20poly1305`

Import it somewhere in your project. Must be done asynchronously (e.g. promise) 

```
import('@dugrema/wasm-xchacha20poly1305/wasm_xchacha20poly1305.js')
    .then( wasmcrypto => { ... do something with it ...} )
```

I'm using React with rescript to rewire support for WASM. Here is the howto I used to understand
how to wire WASM in React : https://koala42.com/using-webassembly-in-your-reactjs-app/. Use this to get your magic
bytes in line.

# Usage

## One-pass: faster, all in memory

* `chacha20poly1305_encrypt(nonce, key, data) -> Array with ciphertext + 16 byte auth tag`
* `chacha20poly1305_decrypt(nonce, key, data, tag) -> Array with deciphered content`
* `xchacha20poly1305_encrypt(nonce, key, data) -> Array with ciphertext + 16 byte auth tag`
* `xchacha20poly1305_decrypt(nonce, key, data, tag) -> Array with deciphered content`

Parameters

* nonce : Uint8Array, 12 bytes for ChaCha20Poly1305 or 24 bytes for XChaCha20Poly1305
* key : Uint8Array, 32 bytes
* data : Uint8Array with data to process.
* tag : 16 byte Array, optional. If not provided, the auth tag *MUST* be in the last 16 bytes of the data parameter.

## Incremental: supports files up to 256 GB from streams

* `chacha20poly1305_encrypt_stream(nonce, key, data)`
* `chacha20poly1305_decrypt_stream(nonce, key, tag, readStream, outputStream)`
* `xchacha20poly1305_encrypt_stream(nonce, key, readStream, outputStream) -> Array with 16 byte auth tag`
* `xchacha20poly1305_decrypt_stream(nonce, key, tag, readStream, outputStream) `

Values

* nonce : Uint8Array, 12 bytes for ChaCha20Poly1305 or 24 bytes for XChaCha20Poly1305
* key : Uint8Array, 32 bytes
* readStream : object with async .read() that returns { done: bool, data: Uint8Array }. See readStream example below
* outputStream : object with async .write(data). See outputStream example below.
* tag : 16 byte Array

## Example

One-pass encryption (no incremental processing) with chacha20poly1305
```
    // Prepare the 32 byte key, 12 byte nonce.
    const key = Buffer.from('808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f', 'hex')
    const nonce = Buffer.from('404142434445464748494a4b', 'hex')  // Not secure, always use a new random nonce! 

    // Prepare the data
    const messageString = "Content to encrypt"
    const encoder = new TextEncoder()
    const messageBytes = encoder.encode(messageString)
    
    // Encrypt in a single pass
    const ciphertextTag = await wasmcrypto.chacha20poly1305_encrypt(nonce, key, messageBytes)

    // Note : ciphertextTag contains both the cipher and the 16 byte tag in a simple Array. 
    //        here is how to extract them to a Buffer
    const ciphertext = Buffer.from(ciphertextTag.slice(0, ciphertextTag.length-16))
    const tag = Buffer.from(ciphertextTag.slice(ciphertextTag.length-16))
```

Stream encryption with xchacha20poly1305
```
async function encrypt() {
    const key = Buffer.from('808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f', 'hex');
    const nonce = Buffer.from('404142434445464748494a4b4c4d4e4f505152', 'hex');
    
    const readStream = ... object with async .read() that returns { done: bool, data: Uint8Array }
    const outputStream = ... object with async .write(data) ...
    
    const tag = await wasmcrypto.xchacha20poly1305_encrypt_stream(nonce, key, readstream, output)
    // Note: the tag is an Array, you can convert it to a Buffer with : Buffer.from(tag) 
}
```

Stream decryption
```
async function decrypt() {
    const key = Buffer.from('808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f', 'hex');
    const nonce = Buffer.from('404142434445464748494a4b4c4d4e4f505152', 'hex');

    const tag = ... your tag from the encryption result ... 
    const readStream = ... object with async .read() that returns { done: bool, data: Uint8Array } ...
    const outputStream = ... object with async .write(data) ...
    
    await wasmcrypto.xchacha20poly1305_decrypt_stream(nonce, key, tag, readStream, outputStream)
}
```

Read stream example 
```
const CHUNK_SIZE = 64 * 1024
function combineBuffers(buffer1, buffer2) {
    let buffers = new Uint8Array(buffer1.length + buffer2.length)
    buffers.set(buffer1, 0)
    buffers.set(buffer2, buffer1.length)
    return buffers
}

let messageBytes = new Uint8Array(100)  // sample data, all zeroes

const readStream = {
    read: async () => {
        if(!messageBytes) {
            return {done: true, value: null}
        }
        let value = Buffer.from(messageBytes.slice(0, CHUNK_SIZE))
        if(value.length === CHUNK_SIZE) {
            messageBytes = messageBytes.slice(CHUNK_SIZE)
        } else {
            messageBytes = null
        }
        return {done: false, value}
    }
}
```

Output stream example
```
const outputStream = {
    write: async chunk => {
        outputData = combineBuffers(outputData, chunk)
        return true
    }
}
```

## Performance

Just to make sure this was worthwhile, I've compared this WASM wrapper to the pure JavaScript library implementation
chacha20-js and poly1305-js (as found on npmjs.org).

When just running chacha20-js (no poly1305-js auth) :

* On my PC (old Xeon running Ubuntu 20 with Firefox), I get about 2x improvement with the WASM wrapper.
* On an iPhone 7, about 5x improvement with the WASM wrapper.
* On an old cheap Umdigi Android, about 2x speed improvement with the WASM wrapper.
