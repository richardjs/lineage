pub trait Block {}

#[derive(Debug, PartialEq)]
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

    pub fn as_bytes(&self) -> [u8; 82] {
        let mut bytes: [u8; 82] = [0; 82];
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

struct SignatureBlock {
    signature: [u8; 64],
}

struct MoveBlock {
    start_square: u8,
    end_square: u8,
    signature: [u8; 64],
}

struct GameChain {
    challenge: ChallengeBlock,
    signatures: [SignatureBlock; 2],
    moves: Vec<MoveBlock>,
}

impl GameChain {
    fn new(&self) {
        //        GameChain {
        //            Challeng
        //        }
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
}
