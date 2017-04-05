// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! Cryptographic operations for `WebPush`.
//!
//! Implemented as described in the draft IETF RFC:
//! https://tools.ietf.org/html/draft-ietf-webpush-encryption-02
//! https://tools.ietf.org/html/draft-ietf-webpush-protocol-04
//! https://tools.ietf.org/html/draft-ietf-httpbis-encryption-encoding-01
//!

extern crate crypto;

use error::{WebPushError, WebPushResult};

use openssl::bn::BigNumContext;
use openssl::ec;
use openssl::nid;
use openssl::pkey;

use self::crypto::aead::AeadDecryptor;
use self::crypto::aead::AeadEncryptor;
use self::crypto::aes_gcm::AesGcm;
use self::crypto::aes::KeySize;
use self::crypto::hkdf::{hkdf_expand, hkdf_extract};
use self::crypto::hmac::Hmac;
use self::crypto::sha2::Sha256;
use self::crypto::mac::Mac;

use std::cmp::min;
use std::sync::{Arc, Mutex};
use rand::Rng;
use rand::os::OsRng;

use rustc_serialize::base64::{FromBase64, ToBase64, URL_SAFE};

const AESGCM_TAG_LEN: usize = 16;

#[derive(Debug)]
pub struct EncryptData {
    pub salt: String,
    pub output: Vec<u8>,
}

struct AuthData {
    pub auth: Vec<u8>,
    pub key_context: Vec<u8>,
}

#[derive(Clone)]
pub struct CryptoContext {
    pub public_key: String,
    key_pair: Arc<Mutex<ec::EcKey>>,
}

unsafe impl Send for CryptoContext {}
unsafe impl Sync for CryptoContext {}

impl CryptoContext {
    pub fn new() -> Option<Self> {
        let mut bn = BigNumContext::new().unwrap();
        let group = ec::EcGroup::from_curve_name(nid::X9_62_PRIME256V1).unwrap();
        let local_key = ec::EcKey::generate(&group).unwrap();

        let public_key_bytes;
        {
            let public_key = local_key.public_key().unwrap();
            public_key_bytes = public_key.to_bytes(&group, ec::POINT_CONVERSION_UNCOMPRESSED, &mut bn).unwrap();
        }

        Some(CryptoContext {
            public_key: public_key_bytes.to_base64(URL_SAFE),
            // This needs to be protected by a mutex because OpenSSL updates
            // the reference count, even if we shouldn't need to modify anything
            // else with the local key.
            key_pair: Arc::new(Mutex::new(local_key)),
        })
    }

    pub fn get_public_key(&self, auth: bool) -> String {
        if auth {
            self.public_key.replace("=", "")
        } else {
            self.public_key.clone()
        }
    }

    pub fn ecdh_derive_keys(&self, peer_key_bytes: &[u8]) -> WebPushResult<Vec<u8>> {
        let mut bn = try!(BigNumContext::new());
        let group = try!(ec::EcGroup::from_curve_name(nid::X9_62_PRIME256V1));
        let peer_ecpoint = try!(ec::EcPoint::from_bytes(&group, peer_key_bytes, &mut bn));
        let peer_eckey = try!(ec::EcKey::from_public_key(&group, &peer_ecpoint));
        let peer_pkey = try!(pkey::PKey::from_ec_key(peer_eckey));

        let key_pair = self.key_pair.lock().unwrap();
        let local_eckey = try!((*key_pair).to_owned());
        let local_pkey = try!(pkey::PKey::from_ec_key(local_eckey));

        let mut ctx = try!(pkey::PKeyCtx::from_pkey(&local_pkey));
        Ok(try!(ctx.derive_from_peer(&peer_pkey)))
    }

    fn aesgcm128_append_key(key_context: &mut Vec<u8>, key: &[u8]) {
        assert!(key.len() <= 255);
        key_context.push(0u8);
        key_context.push(key.len() as u8);
        key_context.extend_from_slice(key);
    }

    fn aesgcm128_auth_data(&self,
                           auth: &Option<String>,
                           peer_key: &[u8],
                           encrypt: bool)
                           -> WebPushResult<Option<AuthData>> {
        let auth_bytes = match *auth {
            Some(ref x) => try!(x.from_base64()),
            None => return Ok(None),
        };

        let local_key = try!(self.public_key.from_base64());

        // Context is used later for encrypt key and nonce derivation
        // https://tools.ietf.org/html/draft-ietf-httpbis-encryption-encoding-01#section-4.2
        //
        //  "context = label || 0x00 ||
        //             length(recipient_public) || recipient_public ||
        //             length(sender_public) || sender_public
        //
        // "The two length fields are encoded as a two octet unsigned integer in
        //  network byte order."
        //
        // The label is "P-256" defined here:
        // https://tools.ietf.org/html/draft-ietf-webpush-encryption-02#section-5
        //
        // "The label for this curve is the string "P-256" encoded in ASCII (that
        //  is, the octet sequence 0x50, 0x2d, 0x32, 0x35, 0x36)."
        let mut key_context: Vec<u8> = Vec::with_capacity(peer_key.len() + local_key.len() + 11);
        key_context.extend_from_slice(b"P-256\x00");
        if encrypt {
            Self::aesgcm128_append_key(&mut key_context, peer_key);
            Self::aesgcm128_append_key(&mut key_context, &local_key);
        } else {
            Self::aesgcm128_append_key(&mut key_context, &local_key);
            Self::aesgcm128_append_key(&mut key_context, peer_key);
        }
        key_context.push(1u8);

        Ok(Some(AuthData {
            auth: auth_bytes,
            key_context: key_context,
        }))
    }

    fn aesgcm128_common(&self,
                        salt: &[u8],
                        shared_key: &[u8],
                        auth: Option<AuthData>)
                        -> ([u8; 32], [u8; 32], [u8; 12]) {
        let sha = Sha256::new();
        let mut encrypt_info: Vec<u8> = Vec::new();
        let mut nonce_info: Vec<u8> = Vec::new();

        // Create the HKDF salt from our shared key and transaction salt
        let mut salt_hmac = Hmac::new(Sha256::new(), salt);
        match auth {
            Some(ad) => {
                // We may have an additional shared secret
                // https://tools.ietf.org/html/draft-ietf-httpbis-encryption-encoding-01#section-4.3
                //
                //       auth_info = "Content-Encoding: auth" || 0x00
                //             IKM = HKDF(authentication, raw_key, auth_info, 32)
                let mut prk = [0u8; 32];
                hkdf_extract(sha, &ad.auth, shared_key, &mut prk);

                let auth_info = b"Content-Encoding: auth\x00";
                let mut ikm = [0u8; 32];
                hkdf_expand(sha, &prk, auth_info, &mut ikm);
                salt_hmac.input(&ikm);

                // https://tools.ietf.org/html/draft-ietf-httpbis-encryption-encoding-01#section-3.2
                //
                // To generate the encryption key:
                //
                // "cek_info = "Content-Encoding: aesgcm" || 0x00 || context"
                // "CEK = HMAC-SHA-256(PRK, cek_info || 0x01)"
                //
                // "Unless otherwise specified, the context is a zero length octet
                //  sequence.  Specifications that use this content encoding MAY specify
                //  the use of an expanded context to cover additional inputs in the key
                //  derivation."
                //
                // https://tools.ietf.org/html/draft-ietf-httpbis-encryption-encoding-01#section-3.3
                //
                // To generate the nonce:
                //
                // "nonce_info = "Content-Encoding: nonce" || 0x00 || context"
                // "NONCE = HMAC-SHA-256(PRK, nonce_info || 0x01) XOR SEQ"
                //
                encrypt_info.extend_from_slice(b"Content-Encoding: aesgcm\x00");
                encrypt_info.extend_from_slice(&ad.key_context);
                nonce_info.extend_from_slice(b"Content-Encoding: nonce\x00");
                nonce_info.extend_from_slice(&ad.key_context);
            }
            None => {
                // Legacy standard/implementation
                //
                // https://tools.ietf.org/html/draft-ietf-httpbis-encryption-encoding-00#section-4.3
                //
                // "Note that in the absence of an authentication secret, the input
                //  keying material is simply the raw keying material:
                //
                //      IKM = raw_key"
                salt_hmac.input(&shared_key[..]);

                // https://tools.ietf.org/html/draft-ietf-httpbis-encryption-encoding-00#section-3.2
                //
                // To generate the encryption key:
                //
                // "cek_info = "Content-Encoding: aesgcm128" || 0x00 || context"
                // "CEK = HMAC-SHA-256(PRK, cek_info || 0x01)"
                //
                // "Unless otherwise specified, the context is a zero length octet
                //  sequence.  Specifications that use this content encoding MAY specify
                //  the use of an expanded context to cover additional inputs in the key
                //  derivation."
                //
                // https://tools.ietf.org/html/draft-ietf-httpbis-encryption-encoding-00#section-3.3
                //
                // To generate the nonce:
                //
                // "nonce_info = "Content-Encoding: nonce" || 0x00 || context"
                // "NONCE = HMAC-SHA-256(PRK, nonce_info || 0x01) XOR SEQ"
                //
                // Note that while context may be empty, we are still missing the 0x00 byte.
                // This is required for interop with Firefox.
                encrypt_info.extend_from_slice(b"Content-Encoding: aesgcm128\x01");
                nonce_info.extend_from_slice(b"Content-Encoding: nonce\x01");
            }
        };

        let hkdf_salt = salt_hmac.result();

        // Create the AES-GCM encryption key
        // https://tools.ietf.org/html/draft-thomson-http-encryption-01#section-3.2
        let mut encrypt_key = [0u8; 32];
        hkdf_extract(sha, hkdf_salt.code(), &encrypt_info, &mut encrypt_key);

        // Create the AES-GCM nonce
        // https://tools.ietf.org/html/draft-thomson-http-encryption-01#section-3.3
        let mut nonce = [0u8; 32];
        hkdf_extract(sha, hkdf_salt.code(), &nonce_info, &mut nonce);

        // Sequence number is the same size as the nonce
        // https://tools.ietf.org/html/draft-thomson-http-encryption-01#section-3.3
        //
        // "The record sequence number (SEQ) is a 96-bit unsigned integer in network
        //  byte order that starts at zero."
        let seq = [0u8; 12];
        (encrypt_key, nonce, seq)
    }

    fn aesgcm128_record_nonce(&self, nonce: &[u8], seq: &mut [u8; 12]) -> [u8; 12] {
        // Generate the nonce for this record
        // https://tools.ietf.org/html/draft-thomson-http-encryption-01#section-3.3
        //
        // "NONCE = HMAC-SHA-256(PRK, "Content-Encoding: nonce" || 0x01) ^ SEQ"
        let mut record_nonce = [0u8; 12];
        let mut i = seq.len();
        while i > 0 {
            i -= 1;
            record_nonce[i] = nonce[i] ^ seq[i];
        }

        // Increment the sequence number in network-order
        i = seq.len();
        while i > 0 {
            i -= 1;
            if seq[i] == 255 {
                seq[i] = 0;
            } else {
                seq[i] += 1;
                break;
            }
        }

        record_nonce
    }

    /// Decrypts the given payload using AES-GCM 128-bit with the shared key and salt.
    /// The shared key and salt are not used directly but rather are used to derive
    /// the encryption key and nonce as defined in the draft RFC.
    fn aesgcm128_decrypt(&self,
                         mut input: Vec<u8>,
                         shared_key: &[u8],
                         salt: &[u8],
                         auth: Option<AuthData>,
                         record_size: usize)
                         -> WebPushResult<String> {
        let has_auth = auth.is_some();
        let (decrypt_key, nonce, mut seq) = self.aesgcm128_common(salt, shared_key, auth);
        let mut chunks = Vec::new();
        let mut total_size = 0;

        while !input.is_empty() {
            let mut bound = min(record_size, input.len());
            if bound <= AESGCM_TAG_LEN {
                return Err(WebPushError::MalformedEncryptedData);
            }
            bound -= AESGCM_TAG_LEN;

            let chunk: Vec<_> = input.drain(0..bound).collect();
            let tag: Vec<_> = input.drain(0..AESGCM_TAG_LEN).collect();
            let record_nonce = self.aesgcm128_record_nonce(&nonce, &mut seq);
            let mut output = vec![0u8; chunk.len()];

            // Fail to decrypt if ends on a record boundary.
            // https://tools.ietf.org/html/draft-ietf-httpbis-encryption-encoding-01#section-2
            //
            // "A sequence of full-sized records can be truncated to produce a
            //  shorter sequence of records with valid authentication tags.  To
            //  prevent an attacker from truncating a stream, an encoder MUST append
            //  a record that contains only padding and is smaller than the full
            //  record size if the final record ends on a record boundary.  A
            //  receiver MUST treat the stream as failed due to truncation if the
            //  final record is the full record size."
            if input.is_empty() && bound == record_size {
                return Err(WebPushError::MalformedEncryptedData);
            }

            let mut cipher = AesGcm::new(KeySize::KeySize128,
                                         &decrypt_key[0..16],
                                         &record_nonce,
                                         &[0; 0]);
            if !cipher.decrypt(&chunk[..], &mut output[..], &tag[..]) {
                return Err(WebPushError::MalformedEncryptedData);
            }

            // Strip padding from the plaintext
            let padding_len = if has_auth {
                let padding: Vec<_> = output.drain(0..2).collect();
                ((padding[0] as usize) << 8) + padding[1] as usize
            } else {
                let padding: Vec<_> = output.drain(0..1).collect();
                padding[0] as usize
            };
            let _: Vec<_> = output.drain(0..padding_len).collect();
            total_size += output.len();
            chunks.push(output);
        }

        let mut out = Vec::with_capacity(total_size);
        for chunk in chunks {
            out.extend_from_slice(&chunk[..]);
        }

        Ok(try!(String::from_utf8(out)))
    }

    /// Encrypts the given payload using AES-GCM 128-bit with the shared key and salt.
    /// The shared key and salt are not used directly but rather are used to derive
    /// the encryption key and nonce as defined in the draft RFC.
    fn aesgcm128_encrypt(&self,
                         input: String,
                         shared_key: &[u8],
                         salt: &[u8; 16],
                         auth: Option<AuthData>,
                         record_size: usize)
                         -> Vec<u8> {
        assert!(!input.is_empty(), "input cannot be empty");
        assert!(record_size > 2,
                "record size must be greater than the padding");

        let has_auth = auth.is_some();
        let (encrypt_key, nonce, mut seq) = self.aesgcm128_common(salt, shared_key, auth);
        let mut raw_input = input.into_bytes();
        let mut chunks = Vec::new();
        let mut padding = false;
        let mut total_size = 0;

        while !raw_input.is_empty() || padding {
            // Add padding to input data in accordance with
            // https://tools.ietf.org/html/draft-ietf-httpbis-encryption-encoding-00#section-2
            //
            // "Padding consists of a length byte, followed that number of zero-valued octets.
            //  A receiver MUST fail to decrypt if any padding octet other than the first is
            //  non-zero"
            //
            // or
            //
            // https://tools.ietf.org/html/draft-ietf-httpbis-encryption-encoding-01#section-2
            //
            // "Padding consists of a two octet unsigned integer in network byte order, followed
            //  that number of zero-valued octets."
            raw_input.insert(0, 0);
            if has_auth {
                raw_input.insert(0, 0);
            }

            let bound = min(record_size, raw_input.len());
            let chunk: Vec<_> = raw_input.drain(0..bound).collect();
            let record_nonce = self.aesgcm128_record_nonce(&nonce, &mut seq);

            // If the final chunk ended on a record boundary, then we
            // need to append one more record with just padding.
            // https://tools.ietf.org/html/draft-thomson-http-encryption-01#section-2
            //
            // "an encoder MUST append a record that contains only padding and is smaller
            //  than the full record size if the final record ends on a record boundary."
            padding = bound == record_size && raw_input.is_empty();

            // With the generation AES-GCM key/nonce pair, encrypt the payload
            let mut cipher = AesGcm::new(KeySize::KeySize128,
                                         &encrypt_key[0..16],
                                         &record_nonce,
                                         &[0; 0]);
            let mut tag = [0u8; AESGCM_TAG_LEN];
            let mut out = vec![0u8; chunk.len() + tag.len()];
            out.truncate(chunk.len());
            cipher.encrypt(&chunk[..], &mut out, &mut tag);

            // Append the authentication tag to the record payload
            // https://tools.ietf.org/html/draft-thomson-http-encryption-01#section-2
            //
            // "Valid records always contain at least one byte of padding and a 16
            // octet authentication tag."
            out.extend_from_slice(&tag);
            total_size += out.len();
            chunks.push(out);
        }

        let mut out = Vec::with_capacity(total_size);
        for chunk in chunks {
            out.extend_from_slice(&chunk[..]);
        }
        out
    }

    /// Encrypt a payload using the given public key according to the `WebPush`
    /// RFC specifications.
    pub fn encrypt(&self,
                   peer_key: &str,
                   input: String,
                   auth: &Option<String>,
                   record_size: usize)
                   -> WebPushResult<EncryptData> {
        // Derive public and secret keys from peer public key
        let peer_key_bytes = try!(peer_key.from_base64());
        let auth_data = try!(self.aesgcm128_auth_data(auth, &peer_key_bytes, true));
        let shared_key = try!(self.ecdh_derive_keys(&peer_key_bytes));

        // Create the salt for this transaction
        // https://tools.ietf.org/html/draft-thomson-http-encryption-01#section-3.1
        //
        // "The "salt" parameter MUST be present, and MUST be exactly 16 octets long
        //  when decoded.  The "salt" parameter MUST NOT be reused for two different
        //  payload bodies that have the same input keying material; generating a
        //  random salt for every application of the content encoding ensures that
        //  content encryption key reuse is highly unlikely."
        let mut gen = OsRng::new().unwrap();
        let mut salt = [0u8; 16];
        gen.fill_bytes(&mut salt);

        let salt_b64 = if auth_data.is_some() {
            salt.to_base64(URL_SAFE).replace("=", "")
        } else {
            salt.to_base64(URL_SAFE)
        };

        Ok(EncryptData {
            salt: salt_b64,
            output: self.aesgcm128_encrypt(input, &shared_key, &salt, auth_data, record_size),
        })
    }

    pub fn decrypt(&self,
                   peer_key: &str,
                   input: Vec<u8>,
                   salt: &str,
                   auth: &Option<String>,
                   record_size: usize)
                   -> WebPushResult<String> {
        // Derive public and secret keys from peer public key
        let peer_key_bytes = try!(peer_key.from_base64());
        let auth_data = try!(self.aesgcm128_auth_data(auth, &peer_key_bytes, false));
        let shared_key = try!(self.ecdh_derive_keys(&peer_key_bytes));
        let salt_bytes = try!(salt.from_base64());

        self.aesgcm128_decrypt(input, &shared_key, &salt_bytes, auth_data, record_size)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn aesgcm128_encrypt_one_record() {
        use super::CryptoContext;

        let crypto = CryptoContext::new().unwrap();
        let input = String::from("test");
        let shared_key = [14, 55, 71, 109, 215, 177, 33, 176, 142, 43, 241, 48, 179, 164, 96, 220, 146, 176, 76, 1, 63, 108, 78, 67, 141, 55, 125, 200, 40, 153, 252, 85];
        let salt = [23, 249, 70, 109, 205, 73, 187, 20, 140, 197, 163, 250, 114, 55, 122, 88];
        let output = crypto.aesgcm128_encrypt(input, &shared_key, &salt, None, 4096);
        let expected = vec![177, 172, 8, 114, 38, 164, 249, 255, 11, 140, 152, 0, 194, 82, 79, 121, 26, 116, 68, 34, 182];
        assert_eq!(output, expected);
    }

    #[test]
    fn aesgcm128_decrypt_one_record() {
        use super::CryptoContext;

        let crypto = CryptoContext::new().unwrap();
        let input = vec![177, 172, 8, 114, 38, 164, 249, 255, 11, 140, 152, 0, 194, 82, 79, 121, 26, 116, 68, 34, 182];
        let shared_key = [14, 55, 71, 109, 215, 177, 33, 176, 142, 43, 241, 48, 179, 164, 96, 220, 146, 176, 76, 1, 63, 108, 78, 67, 141, 55, 125, 200, 40, 153, 252, 85];
        let salt = [23, 249, 70, 109, 205, 73, 187, 20, 140, 197, 163, 250, 114, 55, 122, 88];
        let output = crypto.aesgcm128_decrypt(input, &shared_key, &salt, None, 4096).unwrap();
        assert_eq!(output, String::from("test"));
    }

    #[test]
    fn ecdh_encrypt_and_decrypt_payload() {
        use super::CryptoContext;

        let local = CryptoContext::new().unwrap();
        let peer = CryptoContext::new().unwrap();
        let input = String::from("testing ecdh");
        let auth = None;
        let rs = 4096;
        let encrypt_data = local.encrypt(&peer.public_key, input.clone(), &auth, rs).unwrap();
        let decrypt_data = peer.decrypt(&local.public_key, encrypt_data.output, &encrypt_data.salt, &auth, rs).unwrap();
        assert_eq!(input, decrypt_data);
    }

    #[test]
    fn ecdh_encrypt_and_decrypt_payload_using_auth() {
        use super::CryptoContext;
        use rustc_serialize::base64::{ ToBase64, STANDARD };

        let local = CryptoContext::new().unwrap();
        let peer = CryptoContext::new().unwrap();
        let input = String::from("testing ecdh");
        let auth = Some([0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5].to_base64(STANDARD));
        let rs = 4096;
        let encrypt_data = local.encrypt(&peer.public_key, input.clone(), &auth, rs).unwrap();
        let decrypt_data = peer.decrypt(&local.public_key, encrypt_data.output, &encrypt_data.salt, &auth, rs).unwrap();
        assert_eq!(input, decrypt_data);
    }
}
