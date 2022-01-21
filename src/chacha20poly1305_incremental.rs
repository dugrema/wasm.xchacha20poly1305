//! Core AEAD cipher implementation for (X)ChaCha20Poly1305.
// Copy of the code to add stateful incremental processing.

use core::convert::TryInto;
use poly1305::{
    universal_hash::{NewUniversalHash, UniversalHash},
    Poly1305,
};
use aead::{
    consts::{U0, U12, U16, U24, U32},
    generic_array::{ArrayLength, GenericArray},
    AeadCore, AeadInPlace, Error, NewAead,
    AeadMut,
};

use ::cipher::{NewCipher, StreamCipher, StreamCipherSeek};

use core::marker::PhantomData;
use zeroize::Zeroize;

use chacha20::{ChaCha20, XChaCha20};

const BLOCKSIZE_POLY1305: usize = 16;

/// Size of a ChaCha20 block in bytes
const BLOCK_SIZE: usize = 64;

/// Maximum number of blocks that can be encrypted with ChaCha20 before the
/// counter overflows.
const MAX_BLOCKS: usize = core::u32::MAX as usize;

/// ChaCha20Poly1305 instantiated with a particular nonce
pub(crate) struct Cipher<C>
where
    C: StreamCipher + StreamCipherSeek,
{
    cipher: C,
    mac: Poly1305,
    associated_data_len: usize,
    ciphertext_len: usize,
    aad_set: bool,
    partial_block: Vec<u8>,
}

impl<C> Cipher<C>
where
    C: StreamCipher + StreamCipherSeek,
{
    /// Instantiate the underlying cipher with a particular nonce
    pub(crate) fn new(mut cipher: C) -> Self {
        // Derive Poly1305 key from the first 32-bytes of the ChaCha20 keystream
        let mut mac_key = poly1305::Key::default();
        cipher.apply_keystream(&mut *mac_key);
        let mac = Poly1305::new(GenericArray::from_slice(&*mac_key));
        mac_key.zeroize();

        // Set ChaCha20 counter to 1
        cipher.seek(BLOCK_SIZE as u64);

        Self { cipher, mac, associated_data_len: 0, ciphertext_len: 0, aad_set: false, partial_block: Vec::new() }
    }

    /// Encrypt the given message in-place, returning the authentication tag
    pub(crate) fn encrypt_in_place_detached(
        mut self,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> Result<Tag, Error> {
        if buffer.len() / BLOCK_SIZE >= MAX_BLOCKS {
            return Err(Error);
        }

        self.mac.update_padded(associated_data);

        // TODO(tarcieri): interleave encryption with Poly1305
        // See: <https://github.com/RustCrypto/AEADs/issues/74>
        self.cipher.apply_keystream(buffer);
        self.mac.update_padded(buffer);

        self.authenticate_lengths(associated_data, buffer)?;
        Ok(self.mac.finalize().into_bytes())
    }

    /// Decrypt the given message, first authenticating ciphertext integrity
    /// and returning an error if it's been tampered with.
    pub(crate) fn decrypt_in_place_detached(
        mut self,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &Tag,
    ) -> Result<(), Error> {
        if buffer.len() / BLOCK_SIZE >= MAX_BLOCKS {
            return Err(Error);
        }

        self.mac.update_padded(associated_data);
        self.mac.update_padded(buffer);
        self.authenticate_lengths(associated_data, buffer)?;

        // This performs a constant-time comparison using the `subtle` crate
        if self.mac.verify(tag).is_ok() {
            // TODO(tarcieri): interleave decryption with Poly1305
            // See: <https://github.com/RustCrypto/AEADs/issues/74>
            self.cipher.apply_keystream(buffer);
            Ok(())
        } else {
            Err(Error)
        }
    }

    /// Encrypt the given message in-place, returning the authentication tag
    pub(crate) fn set_aad(
        &mut self,
        associated_data: &[u8],
    ) -> Result<(), Error> {
        if self.aad_set == true {
            return Err(Error);
        }

        self.associated_data_len = associated_data.len();

        // Authenticate the associated data
        self.mac.update_padded(associated_data);

        self.aad_set = true;

        Ok(())
    }

    /// Encrypt the given message in-place, returning the authentication tag
    pub(crate) fn encrypt_update(
        &mut self,
        buffer: &mut [u8],
    ) -> Result<(), Error> {

        self.ciphertext_len += buffer.len();

        if self.ciphertext_len / BLOCK_SIZE >= MAX_BLOCKS {
            return Err(Error);
        }

        // Save emtpy associated data
        if self.aad_set != true {
            self.aad_set = true;
            self.associated_data_len = 0;
            // self.mac.update_padded(&[0u8]);
        }

        // Encrypt data
        self.cipher.apply_keystream(buffer);

        let chunks = if self.partial_block.is_empty() {
            buffer.chunks(BLOCKSIZE_POLY1305)
        } else {
            self.partial_block.extend_from_slice(buffer);
            self.partial_block.chunks(BLOCKSIZE_POLY1305)
        };
        let mut dernier_chunk: Option<Vec<u8>> = None;
        for chunk in chunks {
            if chunk.len() < BLOCKSIZE_POLY1305 {
                // Conserver block partiel
                let mut chunk_vec = Vec::new();
                chunk_vec.extend_from_slice(chunk);
                dernier_chunk = Some(chunk_vec);
            } else {
                let ga = GenericArray::from_slice(chunk);
                self.mac.update(ga);
            }
        }
        self.partial_block.as_mut_slice().zeroize();
        self.partial_block.clear();
        if dernier_chunk.is_some() {
            self.partial_block.extend(dernier_chunk.expect("dernier chunk"));
        }

        Ok(())
    }

    pub(crate) fn encrypt_finalize(mut self) -> Result<Tag, Error> {
        if self.ciphertext_len / BLOCK_SIZE >= MAX_BLOCKS {
            return Err(Error);
        }

        if ! self.partial_block.is_empty() {
            self.mac.update_padded(&self.partial_block[..]);
            self.partial_block.as_mut_slice().zeroize();
            self.partial_block.clear();
        }

        self.authenticate_lengths2()?;
        Ok(self.mac.finalize().into_bytes())
    }

    fn decrypt_update(
        &mut self,
        buffer: &mut [u8],
    ) -> Result<(), Error> {
        self.ciphertext_len += buffer.len();
        if self.ciphertext_len / BLOCK_SIZE >= MAX_BLOCKS {
            return Err(Error);
        }

        if self.aad_set != true {
            self.aad_set = true;
            // self.mac.update_padded(&[0u8]);
            self.associated_data_len = 0;
        }

        let chunks = if self.partial_block.is_empty() {
            buffer.chunks(BLOCKSIZE_POLY1305)
        } else {
            self.partial_block.extend_from_slice(buffer);
            self.partial_block.chunks(BLOCKSIZE_POLY1305)
        };
        let mut dernier_chunk: Option<Vec<u8>> = None;
        for chunk in chunks {
            if chunk.len() < BLOCKSIZE_POLY1305 {
                // Conserver block partiel
                let mut chunk_vec = Vec::new();
                chunk_vec.extend_from_slice(chunk);
                dernier_chunk = Some(chunk_vec);
            } else {
                let ga = GenericArray::from_slice(chunk);
                self.mac.update(ga);
            }
        }
        self.partial_block.as_mut_slice().zeroize();
        self.partial_block.clear();
        if dernier_chunk.is_some() {
            self.partial_block.extend(dernier_chunk.expect("dernier chunk"));
        }

        self.cipher.apply_keystream(buffer);

        Ok(())
    }

    fn decrypt_finalize(mut self, tag: &Tag) -> Result<(), Error> {
        if ! self.partial_block.is_empty() {
            self.mac.update_padded(&self.partial_block[..]);
            self.partial_block.as_mut_slice().zeroize();
            self.partial_block.clear();
        }

        self.authenticate_lengths2()?;

        // This performs a constant-time comparison using the `subtle` crate
        if self.mac.verify(tag).is_ok() {
            Ok(())
        } else {
            Err(Error)
        }
    }

    /// Authenticate the lengths of the associated data and message
    fn authenticate_lengths(&mut self, associated_data: &[u8], buffer: &[u8]) -> Result<(), Error> {
        let associated_data_len: u64 = associated_data.len().try_into().map_err(|_| Error)?;
        let buffer_len: u64 = buffer.len().try_into().map_err(|_| Error)?;

        let mut block = GenericArray::default();
        block[..8].copy_from_slice(&associated_data_len.to_le_bytes());
        block[8..].copy_from_slice(&buffer_len.to_le_bytes());
        self.mac.update(&block);

        Ok(())
    }

    /// Authenticate the lengths of the associated data and message
    fn authenticate_lengths2(&mut self) -> Result<(), Error> {
        let associated_data_len: u64 = self.associated_data_len as u64;
        let buffer_len: u64 = self.ciphertext_len as u64;

        let mut block = GenericArray::default();
        block[..8].copy_from_slice(&associated_data_len.to_le_bytes());
        block[8..].copy_from_slice(&buffer_len.to_le_bytes());
        self.mac.update(&block);

        Ok(())
    }
}

// Key type (256-bits/32-bytes).
///
/// Implemented as an alias for [`GenericArray`].
///
/// All [`ChaChaPoly1305`] variants (including `XChaCha20Poly1305`) use this
/// key type.
pub type Key = GenericArray<u8, U32>;

/// Nonce type (96-bits/12-bytes).
///
/// Implemented as an alias for [`GenericArray`].
pub type Nonce = GenericArray<u8, U12>;

/// XNonce type (192-bits/24-bytes).
///
/// Implemented as an alias for [`GenericArray`].
pub type XNonce = GenericArray<u8, U24>;

/// Poly1305 tag.
///
/// Implemented as an alias for [`GenericArray`].
pub type Tag = GenericArray<u8, U16>;

/// ChaCha20Poly1305 Authenticated Encryption with Additional Data (AEAD).
pub type ChaCha20Poly1305 = ChaChaPoly1305<ChaCha20, U12>;

/// XChaCha20Poly1305 Authenticated Encryption with Additional Data (AEAD).
pub type XChaCha20Poly1305 = ChaChaPoly1305<XChaCha20, U24>;

/// ChaCha8Poly1305 (reduced round variant) Authenticated Encryption with Additional Data (AEAD).
#[cfg(feature = "reduced-round")]
#[cfg_attr(docsrs, doc(cfg(feature = "reduced-round")))]
pub type ChaCha8Poly1305 = ChaChaPoly1305<ChaCha8, U12>;

/// ChaCha12Poly1305 (reduced round variant) Authenticated Encryption with Additional Data (AEAD).
#[cfg(feature = "reduced-round")]
#[cfg_attr(docsrs, doc(cfg(feature = "reduced-round")))]
pub type ChaCha12Poly1305 = ChaChaPoly1305<ChaCha12, U12>;

/// XChaCha8Poly1305 (reduced round variant) Authenticated Encryption with Additional Data (AEAD).
#[cfg(feature = "reduced-round")]
#[cfg_attr(docsrs, doc(cfg(feature = "reduced-round")))]
pub type XChaCha8Poly1305 = ChaChaPoly1305<XChaCha8, U24>;

/// XChaCha12Poly1305 (reduced round variant) Authenticated Encryption with Additional Data (AEAD).
#[cfg(feature = "reduced-round")]
#[cfg_attr(docsrs, doc(cfg(feature = "reduced-round")))]
pub type XChaCha12Poly1305 = ChaChaPoly1305<XChaCha12, U24>;

/// Generic ChaCha+Poly1305 Authenticated Encryption with Additional Data (AEAD) construction.
///
/// See the [toplevel documentation](index.html) for a usage example.
pub struct ChaChaPoly1305<C, N: ArrayLength<u8> = U12>
where
    C: NewCipher<KeySize = U32, NonceSize = N> + StreamCipher + StreamCipherSeek,
{
    /// Secret key
    key: GenericArray<u8, U32>,

    /// ChaCha stream cipher
    stream_cipher: PhantomData<C>,

    stream_cipher2: Option<Cipher<C>>,
}

impl<C, N> NewAead for ChaChaPoly1305<C, N>
where
    C: NewCipher<KeySize = U32, NonceSize = N> + StreamCipher + StreamCipherSeek,
    N: ArrayLength<u8>,
{
    type KeySize = U32;

    fn new(key: &Key) -> Self {

        Self {
            key: *key,
            stream_cipher: PhantomData,
            stream_cipher2: None,
        }
    }
}

impl<C, N> AeadCore for ChaChaPoly1305<C, N>
where
    C: NewCipher<KeySize = U32, NonceSize = N> + StreamCipher + StreamCipherSeek,
    N: ArrayLength<u8>,
{
    type NonceSize = N;
    type TagSize = U16;
    type CiphertextOverhead = U0;
}

impl<C, N> AeadInPlace for ChaChaPoly1305<C, N>
where
    C: NewCipher<KeySize = U32, NonceSize = N> + StreamCipher + StreamCipherSeek,
    N: ArrayLength<u8>,
{
    fn encrypt_in_place_detached(
        &self,
        nonce: &aead::Nonce<Self>,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> Result<Tag, Error> {
        Cipher::new(C::new(&self.key, nonce)).encrypt_in_place_detached(associated_data, buffer)
    }

    fn decrypt_in_place_detached(
        &self,
        nonce: &aead::Nonce<Self>,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &Tag,
    ) -> Result<(), Error> {
        Cipher::new(C::new(&self.key, nonce)).decrypt_in_place_detached(
            associated_data,
            buffer,
            tag,
        )
    }

}

impl<C, N> Clone for ChaChaPoly1305<C, N>
where
    C: NewCipher<KeySize = U32, NonceSize = N> + StreamCipher + StreamCipherSeek,
    N: ArrayLength<u8>,
{
    fn clone(&self) -> Self {
        Self {
            key: self.key,
            stream_cipher: PhantomData,
            stream_cipher2: None,
        }
    }
}

impl<C, N> Drop for ChaChaPoly1305<C, N>
where
    C: NewCipher<KeySize = U32, NonceSize = N> + StreamCipher + StreamCipherSeek,
    N: ArrayLength<u8>,
{
    fn drop(&mut self) {
        self.key.as_mut_slice().zeroize();
    }
}

impl<C, N> AeadUpdate for ChaChaPoly1305<C, N>
where
    C: NewCipher<KeySize = U32, NonceSize = N> + StreamCipher + StreamCipherSeek,
    N: ArrayLength<u8>,
{
    fn set_nonce(&mut self, nonce: &aead::Nonce<Self>) {
        let cipher = Cipher::new(C::new(&self.key, nonce));
        self.stream_cipher2 = Some(cipher);
    }

    fn encrypt_update(
        &mut self,
        buffer: &mut [u8],
    ) -> Result<(), Error> {
        self.stream_cipher2.as_mut().expect("cipher").encrypt_update(buffer)
    }

    fn encrypt_finalize(mut self) -> Result<Tag, Error> {
        let cipher = self.stream_cipher2.take();
        cipher.expect("cipher").encrypt_finalize()
    }

    fn decrypt_update(
        &mut self,
        buffer: &mut [u8],
    ) -> Result<(), Error> {
        self.stream_cipher2.as_mut().expect("cipher").decrypt_update(buffer)
    }

    fn decrypt_finalize(mut self, tag: &Tag) -> Result<(), Error> {
        let cipher = self.stream_cipher2.take();
        cipher.expect("cipher").decrypt_finalize(tag)
    }
}

pub trait AeadUpdate: AeadCore {

    fn set_nonce(&mut self, nonce: &aead::Nonce<Self>);

    fn encrypt_update(
        &mut self,
        buffer: &mut [u8],
    ) -> Result<(), Error>;

    fn encrypt_finalize(self) -> Result<Tag, Error>;

    fn decrypt_update(
        &mut self,
        buffer: &mut [u8],
    ) -> Result<(), Error>;

    fn decrypt_finalize(self, tag: &Tag) -> Result<(), Error>;
}