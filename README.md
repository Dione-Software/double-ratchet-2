# double-ratchet-2

Implementation of the double ratchet system/encryption as specified by [Signal][1].

The implementation follows the cryptographic recommendations provided by [Signal][2].
The AEAD Algorithm uses a constant Nonce. This might be changed in the future.

## Example Usage:

### Standard:
```rust
use double_ratchet_2::ratchet::Ratchet;

let sk = [1; 32];                                                 // Initial Key created by a symmetric key agreement protocol
let (mut bob_ratchet, public_key) = Ratchet::init_bob(sk);        // Creating Bobs Ratchet (returns Bobs PublicKey)
let mut alice_ratchet = Ratchet::init_alice(sk, public_key);      // Creating Alice Ratchet with Bobs PublicKey
let data = b"Hello World".to_vec();                               // Data to be encrypted

let (header, encrypted) = alice_ratchet.ratchet_encrypt(&data);   // Encrypting message with Alice Ratchet (Alice always needs to send the first message)
let decrypted = bob_ratchet.ratchet_decrypt(&header, &encrypted); // Decrypt message with Bobs Ratchet
assert_eq!(data, decrypted)
```

### With lost message:
```rust

let sk = [1; 32];                                                 // Initial Key created by a symmetric key agreement protocol
let (mut bob_ratchet, public_key) = Ratchet::init_bob(sk);        // Creating Bobs Ratchet (returns Bobs PublicKey)
let mut alice_ratchet = Ratchet::init_alice(sk, public_key);      // Creating Alice Ratchet with Bobs PublicKey
let data = b"Hello World".to_vec();                               // Data to be encrypted

let (header1, encrypted1) = alice_ratchet.ratchet_encrypt(&data); // Lost message
let (header2, encrypted2) = alice_ratchet.ratchet_encrypt(&data); // Successful message

let decrypted2 = bob_ratchet.ratchet_decrypt(&header2, &encrypted2); // Decrypting second message first
let decrypted1 = bob_ratchet.ratchet_decrypt(&header1, &encrypted1); // Decrypting latter message

let comp = decrypted1 == data && decrypted2 == data;
assert!(comp);
```

### Encryption before recieving inital message

```rust
use double_ratchet_2::ratchet::Ratchet;
let sk = [1; 32];

let (mut bob_ratchet, _) = Ratchet::init_bob(sk);
let data = b"Hello World".to_vec();

let (_, _) = bob_ratchet.ratchet_encrypt(&data);
```

### Encryption after recieving initial message
However bob can (of course) also encrypt messages. This is possible, after decrypting the first message from alice.

```rust
use double_ratchet_2::ratchet::Ratchet;
let sk = [1; 32];

let (mut bob_ratchet, public_key) = Ratchet::init_bob(sk);
let mut alice_ratchet = Ratchet::init_alice(sk, public_key);

let data = b"Hello World".to_vec();

let (header1, encrypted1) = alice_ratchet.ratchet_encrypt(&data);
let _decrypted1 = bob_ratchet.ratchet_decrypt(&header1, &encrypted1);

let (header2, encrypted2) = bob_ratchet.ratchet_encrypt(&data);
let decrypted2 = alice_ratchet.ratchet_decrypt(&header2, &encrypted2);

assert_eq!(data, decrypted2);
```
### Constructing and Deconstructing Headers

```rust
let header_bytes: Vec<u8> = header.clone().into();
let header_const = Header::from(header_bytes);
assert_eq!(header, header_const);
```

## Features

Currently the crate only supports one feature: ring. If feature is enabled the crate switches
to ring-compat and uses ring as backend for Sha512 Hashing. May result in slightly better performance.


TODO:
- [x] Standard Double Ratchet
- [ ] [Double Ratchet with encrypted headers][3]

[1]: https://signal.org/docs/specifications/doubleratchet/
[2]: https://signal.org/docs/specifications/doubleratchet/#recommended-cryptographic-algorithms
[3]: https://signal.org/docs/specifications/doubleratchet/#double-ratchet-with-header-encryption
