extern crate ring;
extern crate untrusted;

use ring::{
    rand::{SecureRandom, SystemRandom},
    signature::{self, Ed25519KeyPair},
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

pub fn sign(key_pair: &Ed25519KeyPair, msg: &[u8]) -> Vec<u8> {
    key_pair.sign(msg).as_ref().iter().cloned().collect()
}

pub fn verify(public_key: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    signature::verify(
        &signature::ED25519,
        Input::from(public_key),
        Input::from(msg),
        Input::from(sig),
    )
    .is_ok()
}
