use std::{collections::HashMap, sync::Arc};

use hex::FromHex;
use sequoia_openpgp::{cert::CertBuilder, parse::Parse, serialize::Serialize, Cert};
use tempfile::tempdir;

use crate::{
    crypto::{slice_to_20_bytes, Crypto, CryptoImpl, GpgMe},
    signature::Recipient,
};

#[test]
pub fn crypto_impl_from() {
    assert_eq!(CryptoImpl::GpgMe, CryptoImpl::try_from("gpg").unwrap());
}

#[test]
pub fn crypto_impl_from_error() {
    assert!(CryptoImpl::try_from("random").is_err());
}

#[test]
pub fn crypto_impl_display() {
    assert_eq!("gpg", format!("{}", CryptoImpl::GpgMe));
}

#[test]
pub fn slice_to_20_bytes_failure() {
    let input = [3; 16];

    let result = slice_to_20_bytes(&input);

    assert!(result.is_err());
}

#[test]
pub fn slice_to_20_bytes_success() {
    let input = [3; 20];

    let result = slice_to_20_bytes(&input).unwrap();

    assert_eq!(input, result);
}

fn cert() -> Arc<Cert> {
    Arc::new(
        Cert::from_bytes(
            b"-----BEGIN PGP PUBLIC KEY BLOCK-----

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
=+GpQ
-----END PGP PUBLIC KEY BLOCK-----
",
        )
        .unwrap(),
    )
}

fn fingerprint() -> [u8; 20] {
    [
        0x7E, 0x06, 0x80, 0x70, 0xD5, 0xEF, 0x79, 0x4B, 0x00, 0xC8, 0xA9, 0xD9, 0x1D, 0x10, 0x8E,
        0x6C, 0x07, 0xCB, 0xC4, 0x06,
    ]
}
