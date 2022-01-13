# wasm.xchacha20poly1305
WASM version of XChaCha20Poly1305 streaming in rust

References implementation of XChaCha20Poly1305

## Description

This is a simple WASM wrapper around the Rust crate chacha20poly1305. Currently the only algorithm
exposed is the block streaming version of XChaCha20POly1305.

The blocksize is hard-coded to 256Kb (why? because it's a positive integer). All the auth tags are included in the
stream. This means 16 bytes are added to the original stream for each block.

## References

Github : https://github.com/dugrema/wasm.xchacha20poly1305

* https://docs.rs/chacha20poly1305/latest/chacha20poly1305/index.html
* https://koala42.com/using-webassembly-in-your-reactjs-app/

# How to install

Add to your project, for example using npm:

`npm install @dugrema/wasm-crypto`

Import it somewhere in your project. Must be done asynchronously (e.g. promise) 

`import('@dugrema/wasm-crypto/dugrema_wasm_xchacha20poly1305.js').then(wasmcrypto=>{ ... do something with it ...})`

I'm using React with rescript to rewire support for WASM. Here is the howto I used to understand
how to wire WASM in React : https://koala42.com/using-webassembly-in-your-reactjs-app/. Use this to get your magic
bytes in line.

# Usage

* `xchacha20poly1305_encrypt_stream(nonce, key, readStream, outputStream)`
* `xchacha20poly1305_decrypt_stream(nonce, key, readStream, outputStream)`

Values

* nonce : Uint8Array
* key : Uint8Array
* readStream : object with async .read() that returns { done: bool, data: Uint8Array }. See readStream example below
* outputStream : object with async .write(data). See outputStream example below.

## Example

Stream encryption
```
async function encrypt() {
    const key = Buffer.from('808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f', 'hex');
    const nonce = Buffer.from('404142434445464748494a4b4c4d4e4f505152', 'hex');
    
    const readStream = ... object with async .read() that returns { done: bool, data: Uint8Array }
    const outputStream = ... object with async .write(data) ...
    
    await wasmcrypto.xchacha20poly1305_encrypt_stream(nonce, key, readStream, outputStream)
}
```

Stream decryption
```
async function decrypt() {
    const key = Buffer.from('808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f', 'hex');
    const nonce = Buffer.from('404142434445464748494a4b4c4d4e4f505152', 'hex');
    
    const readStream = ... object with async .read() that returns { done: bool, data: Uint8Array } ...
    const outputStream = ... object with async .write(data) ...
    
    await wasmcrypto.xchacha20poly1305_decrypt_stream(nonce, key, readStream, outputStream)
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
