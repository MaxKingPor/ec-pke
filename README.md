## Usage
```Rust
use ec_pke::{EcDecrypt, EcEncrypt, Cipher, Mode};
use sm2::SecretKey;
use rand_core::OsRng;
// Encrypting
let secret_key = SecretKey::random(&mut OsRng);
let public_key = secret_key.public_key();
let plaintext = b"plaintext";
let cipher = public_key.encrypt(plaintext).unwrap();
let ciphertext = cipher.to_vec(Mode::C1C3C2);
// Decrypting
let cipher = Cipher::from_slice(&ciphertext, Mode::C1C3C2).unwrap();
let ciphertext = secret_key.decrypt(&cipher).unwrap();
assert_eq!(ciphertext, plaintext)
 ```