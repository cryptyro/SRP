use std::str::FromStr;

use sha2::{Sha256, Digest}; // Importing SHA-256 functions
use num_bigint::{BigUint, RandBigInt};
use rand::thread_rng;
use lazy_static::lazy_static;

// Define the prime p , base g and multplier k as global values using lazy_static
lazy_static! {
    pub static ref P: BigUint = BigUint::parse_bytes(
        b"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327fffffffffffffffff", 16).unwrap();
    pub static ref G: BigUint = BigUint::from(2u32);
    pub static ref K: BigUint = BigUint::from(3u32);
}

pub fn login_responsee_generator(client_pk: &String, verifier: &String) -> (BigUint, String){
    let A = BigUint::from_str(client_pk).unwrap();
    let v = BigUint::from_str(verifier).unwrap();
    
    let mut rng = thread_rng();
    let b = rng.gen_biguint_below(&P);

    let temp1 = G.modpow(&b, &P);
    let server_pk = ((&K.clone() * &v) + &temp1) % &P.clone();

    let concatenated = format!("{}{}", client_pk, server_pk.to_string());
    let mut hasher = Sha256::new();
    hasher.update(concatenated);
    let hash = hasher.finalize();
    let temp2 = hex::encode(hash);
    let u=  BigUint::parse_bytes(temp2.as_bytes(), 16).unwrap();

    let temp3 = v.modpow(&u, &P);
    let S = (&A * &temp3).modpow(&b, &P);
    let mut hasher = Sha256::new();
    hasher.update(S.to_string());
    let k = hasher.finalize();

    let session_key = hex::encode(k);
    println!("session parameter: {}, session key: {}",S,session_key);

    return(server_pk, session_key);
}

pub fn verifier_generator(salt: String, password: String)->String{
    let concatenated = format!("{}{}", salt, password);
    let mut hasher = Sha256::new();
    hasher.update(concatenated);
    let hash = hasher.finalize();
    let temp = hex::encode(hash);
    let x=  BigUint::parse_bytes(temp.as_bytes(), 16).unwrap();
    let verifier = G.modpow(&x, &P);
    //println!("verifier is:{}",verifier);

    return verifier.to_string()
}