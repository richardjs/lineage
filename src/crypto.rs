extern crate ring;
extern crate untrusted;

use ring::{
    rand::{SecureRandom, SystemRandom},
    signature::{self, Ed25519KeyPair, KeyPair},
};
use untrusted::Input;

pub fn new_rng() -> SystemRandom {
    SystemRandom::new()
}

pub fn generate_key(rng: &dyn SecureRandom) -> Ed25519KeyPair {
    Ed25519KeyPair::from_pkcs8(Input::from(
        Ed25519KeyPair::generate_pkcs8(rng).unwrap().as_ref(),
    ))
    .unwrap()
}

pub fn verify(
    public_key: &Ed25519KeyPair,
    msg: &[u8],
    sig: &[u8],
) -> Result<(), ring::error::Unspecified> {
    signature::verify(
        &signature::ED25519,
        Input::from(public_key.public_key().as_ref()),
        Input::from(msg),
        Input::from(sig),
    )
}
