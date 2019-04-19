use crate::crypto;

use ring::signature::{Ed25519KeyPair, KeyPair};

pub trait Block {}

#[derive(Clone, Debug, PartialEq)]
pub struct ChallengeBlock {
    version: u8,
    network_id: u8,
    id: u32,
    white_public_key: [u8; 32],
    black_public_key: [u8; 32],
    paired_game_id: u32,
    timestamp: u64,
}

impl ChallengeBlock {
    pub fn new(white_public_key: &[u8], black_public_key: &[u8]) -> ChallengeBlock {
        let mut white_bytes: [u8; 32] = [0; 32];
        white_bytes.copy_from_slice(&white_public_key);
        let mut black_bytes: [u8; 32] = [0; 32];
        black_bytes.copy_from_slice(&black_public_key);

        ChallengeBlock {
            version: 0,
            network_id: 0,
            id: 0, //TODO make random,
            white_public_key: white_bytes,
            black_public_key: black_bytes,
            paired_game_id: 0,
            timestamp: 0, // TODO make timestamp
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> ChallengeBlock {
        let mut id_bytes = [0; 4];
        id_bytes.copy_from_slice(&bytes[2..6]);
        let mut white_public_key = [0; 32];
        white_public_key.copy_from_slice(&bytes[6..38]);
        let mut black_public_key = [0; 32];
        black_public_key.copy_from_slice(&bytes[38..70]);
        let mut paired_game_id_bytes = [0; 4];
        paired_game_id_bytes.copy_from_slice(&bytes[70..74]);
        let mut timestamp_bytes = [0; 8];
        timestamp_bytes.copy_from_slice(&bytes[74..82]);

        ChallengeBlock {
            version: bytes[0],
            network_id: bytes[1],
            id: u32::from_be_bytes(id_bytes),
            white_public_key,
            black_public_key,
            paired_game_id: u32::from_be_bytes(paired_game_id_bytes),
            timestamp: u64::from_be_bytes(timestamp_bytes),
        }
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![0; 82];
        bytes[0] = self.version;
        bytes[1] = self.network_id;
        bytes[2..6].copy_from_slice(&self.id.to_be_bytes());
        bytes[6..38].copy_from_slice(&self.white_public_key);
        bytes[38..70].copy_from_slice(&self.black_public_key);
        bytes[70..74].copy_from_slice(&self.paired_game_id.to_be_bytes());
        bytes[74..82].copy_from_slice(&self.timestamp.to_be_bytes());
        bytes
    }
}

#[derive(Clone, Debug, PartialEq)]
struct AcceptBlock {
    signature: Vec<u8>,
}

impl AcceptBlock {
    fn new(challenge: &ChallengeBlock, key_pair: &Ed25519KeyPair) -> AcceptBlock {
        let challenge_bytes = challenge.as_bytes();
        AcceptBlock {
            signature: crypto::sign(key_pair, &challenge_bytes),
        }
    }

    fn from_bytes(bytes: &[u8]) -> Result<AcceptBlock, &str> {
        if bytes.len() < 64 {
            return Err("Not enough bytes to create accept block.");
        }
        let mut signature = vec![0; 64];
        signature.copy_from_slice(&bytes[..64]);
        Ok(AcceptBlock { signature })
    }

    fn as_bytes(&self) -> Vec<u8> {
        self.signature.clone()
    }
}

#[derive(Debug, PartialEq)]
struct MoveBlock {
    start_square: u8,
    end_square: u8,
    signature: Vec<u8>,
}

#[derive(Debug, PartialEq)]
pub struct GameChain {
    challenge: ChallengeBlock,
    accepts: [Option<AcceptBlock>; 2],
    moves: Vec<MoveBlock>,
}

impl GameChain {
    pub fn new(challenge: ChallengeBlock) -> GameChain {
        GameChain {
            challenge,
            accepts: [None, None],
            moves: Vec::new(),
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<GameChain, &str> {
        if bytes.len() < 82 {
            return Err("Not enough bytes to create challenge block.");
        }
        let challenge = ChallengeBlock::from_bytes(&bytes);
        let mut chain = GameChain::new(challenge);
        if let Ok(accept) = AcceptBlock::from_bytes(&bytes[82..]) {
            chain.accepts[0] = Some(accept);
        } else {
            return Ok(chain);
        }
        if let Ok(accept) = AcceptBlock::from_bytes(&bytes[82 + 64..]) {
            chain.accepts[1] = Some(accept);
        } else {
            return Ok(chain);
        }
        Ok(chain)
    }

    pub fn sign(&mut self, key_pair: &Ed25519KeyPair) -> Result<(), &str> {
        let mut public_key_bytes: [u8; 32] = [0; 32];
        public_key_bytes.copy_from_slice(key_pair.public_key().as_ref());
        if public_key_bytes != self.challenge.white_public_key
            && public_key_bytes != self.challenge.black_public_key
        {
            return Err("This key is not in the challenge block.");
        }

        if self.accepts[0].is_none() && self.accepts[1].is_some() {
            self.accepts[0] = self.accepts[1].clone();
            self.accepts[1] = None;
        }

        if self.accepts[0].is_none() {
            self.accepts[0] = Some(AcceptBlock::new(&self.challenge, key_pair));
            return Ok(());
        } else if self.accepts[1].is_none() {
            if crypto::verify(
                &public_key_bytes,
                &self.challenge.as_bytes(),
                &self.accepts[0].clone().unwrap().signature,
            ) {
                return Err("This key is already present in the chain.");
            }
            self.accepts[1] = Some(AcceptBlock::new(&self.challenge, key_pair));
            return Ok(());
        } else {
            return Err("There are already two signatures on this chain.");
        }
    }

    pub fn verify(&self) -> bool {
        if self.accepts[0].is_none() || self.accepts[1].is_none() {
            return false;
        }
        if (crypto::verify(
            &self.challenge.white_public_key,
            &self.challenge.as_bytes(),
            &self.accepts[0].clone().unwrap().signature,
        ) && crypto::verify(
            &self.challenge.black_public_key,
            &self.challenge.as_bytes(),
            &self.accepts[1].clone().unwrap().signature,
        )) || (crypto::verify(
            &self.challenge.white_public_key,
            &self.challenge.as_bytes(),
            &self.accepts[1].clone().unwrap().signature,
        ) && crypto::verify(
            &self.challenge.black_public_key,
            &self.challenge.as_bytes(),
            &self.accepts[0].clone().unwrap().signature,
        )) {
            return true;
        }
        return false;
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let mut bytes = self.challenge.as_bytes();
        if self.accepts[0].is_none() {
            return bytes;
        }
        bytes.extend(self.accepts[0].clone().unwrap().as_bytes());
        if self.accepts[1].is_none() {
            return bytes;
        }
        bytes.extend(self.accepts[1].clone().unwrap().as_bytes());
        bytes
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::crypto;
    use ring::signature::KeyPair;

    #[test]
    fn challenge_to_bytes_and_back() {
        let rng = crypto::new_rng();
        let white = crypto::generate_key(&rng);
        let black = crypto::generate_key(&rng);
        let challenge =
            ChallengeBlock::new(white.public_key().as_ref(), black.public_key().as_ref());
        assert_eq!(challenge, ChallengeBlock::from_bytes(&challenge.as_bytes()));
    }

    #[test]
    fn sign_and_verify_chain() {
        let rng = crypto::new_rng();
        let white = crypto::generate_key(&rng);
        let black = crypto::generate_key(&rng);
        let challenge =
            ChallengeBlock::new(white.public_key().as_ref(), black.public_key().as_ref());
        let mut chain = GameChain::new(challenge.clone());
        chain.sign(&white);
        chain.sign(&black);
        assert!(chain.verify());

        chain = GameChain::new(challenge);
        chain.sign(&black);
        chain.sign(&white);
        assert!(chain.verify());
    }

    #[test]
    fn chain_verify_fails() {
        let rng = crypto::new_rng();
        let white = crypto::generate_key(&rng);
        let black = crypto::generate_key(&rng);
        let challenge =
            ChallengeBlock::new(white.public_key().as_ref(), black.public_key().as_ref());
        let mut chain = GameChain::new(challenge);

        assert!(!chain.verify());

        chain.sign(&white);
        assert!(!chain.verify());

        // sign a second time with the same key (shouldn't work)
        chain.sign(&white);
        assert!(!chain.verify());

        // duplicate the key so both accept blocks will verify (but only for one color)
        chain.accepts[1] = chain.accepts[0].clone();
        assert!(!chain.verify());
    }

    #[test]
    fn chain_to_bytes_and_back() {
        let rng = crypto::new_rng();
        let white = crypto::generate_key(&rng);
        let black = crypto::generate_key(&rng);
        let challenge =
            ChallengeBlock::new(white.public_key().as_ref(), black.public_key().as_ref());
        assert_eq!(challenge, ChallengeBlock::from_bytes(&challenge.as_bytes()));
        let mut chain = GameChain::new(challenge.clone());
        chain.sign(&white);
        chain.sign(&black);

        assert_eq!(chain, GameChain::from_bytes(&chain.as_bytes()).unwrap());
        dbg!(chain.as_bytes().len());
    }
}
