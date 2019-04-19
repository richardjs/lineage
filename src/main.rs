extern crate lineage;

extern crate bs58;
extern crate ring;
extern crate untrusted;

use std::io::prelude::*;

use std::net::{TcpListener, TcpStream};

use ring::signature::KeyPair;

fn main() {
    println!("setting up RNG...");
    let rng = lineage::crypto::new_rng();

    println!("generating key...");
    let white = lineage::crypto::generate_key(&rng);

    let black = lineage::crypto::generate_key(&rng);

    let challenge = lineage::block::ChallengeBlock::new(
        white.public_key().as_ref(),
        black.public_key().as_ref(),
    );

    //    let listener = TcpListener::bind("0.0.0.0:10152").unwrap();
    //
    //    for stream in listener.incoming() {
    //        let mut stream = stream.unwrap();
    //
    //        let mut msg = String::new();
    //        stream.read_to_string(&mut msg);
    //        println!("{}", msg);
    //        stream.write(msg.as_ref());
    //        stream.flush();
    //    }
}
