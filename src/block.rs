use crate::crypto;

use chess::{Action, Color, Game, MoveGen};
use ring::signature::{Ed25519KeyPair, KeyPair};

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

#[derive(Clone, Debug, PartialEq)]
struct MoveBlock {
    start_square: u8,
    end_square: u8,
    signature: Vec<u8>,
}

impl MoveBlock {
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![self.start_square, self.end_square];
        bytes.extend(&self.signature);
        bytes
    }
}

#[derive(Clone, Debug, PartialEq)]
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
        // TODO change challenge::from_bytes to use Result
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

    pub fn get_game(&self) -> Game {
        let mut game = Game::new();
        'next_block: for move_block in &self.moves {
            for mv in MoveGen::new_legal(&game.current_position()) {
                if move_block.start_square == mv.get_source().to_int()
                    && move_block.end_square == mv.get_dest().to_int()
                {
                    game.make_move(mv);
                    continue 'next_block;
                }
            }
            panic!("Invalid game chain!");
        }
        game
    }

    pub fn accept(&mut self, key_pair: &Ed25519KeyPair) -> Result<(), &str> {
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

    pub fn make_move_block(
        &mut self,
        key_pair: &Ed25519KeyPair,
        action: Action,
    ) -> Result<(), &str> {
        let game = self.get_game();

        let public_key_to_move = match game.side_to_move() {
            Color::White => self.challenge.white_public_key,
            Color::Black => self.challenge.black_public_key,
        };
        if public_key_to_move != key_pair.public_key().as_ref() {
            return Err("This key cannot sign the current move.");
        }

        let block = match action {
            Action::MakeMove(mv) => {
                let start_square = mv.get_source().to_int();
                let end_square = mv.get_dest().to_int();

                if !game.current_position().legal(mv) {
                    return Err("Invalid move.");
                }

                let mut chain_bytes = self.as_bytes();
                chain_bytes.push(start_square);
                chain_bytes.push(end_square);
                let signature = crypto::sign(key_pair, &chain_bytes);
                MoveBlock {
                    start_square,
                    end_square,
                    signature,
                }
            }
            _ => {
                return Err("Action not implemented");
            }
        };

        self.moves.push(block);

        Ok(())
    }

    pub fn verify(&self) -> bool {
        if self.accepts[0].is_none() || self.accepts[1].is_none() {
            return false;
        }
        if !((crypto::verify(
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
        ))) {
            return false;
        }

        let mut chain = self.clone();
        chain.moves = Vec::new();
        let mut keys = (
            chain.challenge.white_public_key,
            chain.challenge.black_public_key,
        );
        for move_block in &self.moves {
            let mut bytes = chain.as_bytes();
            bytes.push(move_block.start_square);
            bytes.push(move_block.end_square);
            if !crypto::verify(&keys.0, &bytes, &move_block.signature) {
                return false;
            }
            chain.moves.push(move_block.clone());
            keys = (keys.1, keys.0);
        }

        return true;
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

        for move_block in &self.moves {
            bytes.extend(move_block.as_bytes());
        }

        bytes
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::crypto;
    use chess::{ChessMove, Square};
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
        assert!(chain.accept(&white).is_ok());
        assert!(chain.accept(&black).is_ok());
        assert!(chain.verify());

        chain = GameChain::new(challenge);
        assert!(chain.accept(&white).is_ok());
        assert!(chain.accept(&black).is_ok());
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

        assert!(chain.accept(&white).is_ok());
        assert!(!chain.verify());

        // sign a second time with the same key (shouldn't work)
        assert!(!chain.accept(&white).is_ok());
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
        assert!(chain.accept(&white).is_ok());
        assert!(chain.accept(&black).is_ok());

        assert_eq!(chain, GameChain::from_bytes(&chain.as_bytes()).unwrap());
    }

    #[test]
    fn make_moves() {
        let rng = crypto::new_rng();
        let white = crypto::generate_key(&rng);
        let black = crypto::generate_key(&rng);
        let challenge =
            ChallengeBlock::new(white.public_key().as_ref(), black.public_key().as_ref());
        assert_eq!(challenge, ChallengeBlock::from_bytes(&challenge.as_bytes()));
        let mut chain = GameChain::new(challenge.clone());
        assert!(chain.accept(&white).is_ok());
        assert!(chain.accept(&black).is_ok());

        assert!(chain
            .make_move_block(
                &white,
                Action::MakeMove(ChessMove::new(
                    Square::from_string("e2".to_string()).unwrap(),
                    Square::from_string("e4".to_string()).unwrap(),
                    None,
                )),
            )
            .is_ok());
        assert!(chain.verify());
        assert!(chain
            .make_move_block(
                &black,
                Action::MakeMove(ChessMove::new(
                    Square::from_string("e7".to_string()).unwrap(),
                    Square::from_string("e5".to_string()).unwrap(),
                    None,
                )),
            )
            .is_ok());
        assert!(chain.verify());
        assert!(chain
            .make_move_block(
                &white,
                Action::MakeMove(ChessMove::new(
                    Square::from_string("f2".to_string()).unwrap(),
                    Square::from_string("f4".to_string()).unwrap(),
                    None,
                )),
            )
            .is_ok());
        assert!(chain.verify());

        chain.moves[0].signature[0] += 1;
        assert!(!chain.verify());
        chain.moves[0].signature[0] -= 1;
        assert!(chain.verify());
        chain.moves[2].signature[0] += 1;
        assert!(!chain.verify());
        chain.moves[2].signature[0] -= 1;
        assert!(chain.verify());
    }
}
