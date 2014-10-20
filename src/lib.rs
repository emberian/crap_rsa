extern crate gmp;
extern crate libc;
#[cfg(test)] extern crate test;

// The implementation here is quite inefficient. In particular, the Chinese remainder theorem could
// be used to speed up decryption, and some constants can be precomputed.

use gmp::Mpz;

pub struct PrivateKey {
    pub d: Mpz,
    pub n: Mpz,
}

pub struct PublicKey {
    pub e: Mpz,
    pub n: Mpz,
}

pub struct KeyPair {
    pub private: PrivateKey,
    pub public: PublicKey,
}

fn random_prime(modulus: &Mpz, state: &mut gmp::RandState, confidence: u32) -> Mpz {
    let mut candidate = state.urandom(modulus);

    while candidate.millerrabin(confidence as libc::c_int) == 0 {
        candidate = state.urandom(modulus);
    }

    candidate
}

fn distinct_prime(modulus: &Mpz, other: &Mpz, state: &mut gmp::RandState, confidence: u32) -> Mpz {
    let mut candidate = random_prime(modulus, state, confidence);

    while other == &candidate {
        candidate = random_prime(modulus, state, confidence);
    }

    candidate
}

fn from(x: u64) -> Mpz {
    FromPrimitive::from_u64(x).unwrap()
}

impl KeyPair {
    /// Generate an n-bit keypair
    pub fn generate(n: &Mpz) -> KeyPair {
        let mut rand = gmp::RandState::new();

        let one: Mpz = from(1);
        let p = random_prime(n, &mut rand, 50);
        let q = distinct_prime(n, &p, &mut rand, 50);
        let n = p * q;
        let phi_n = (p - one) * (q - one);
        // recommended by boneh's survey of rsa
        // (http://crypto.stanford.edu/~dabo/abstracts/RSAattack-survey.html)
        let e: Mpz = from(65537);
        // returns (gcd, x, y) where gcd = x*a + y*b. our d is y.
        let d: Mpz = e.gcdext(&phi_n).val2();

        KeyPair {
            private: PrivateKey {
                d: d,
                n: n.clone(),
            },
            public: PublicKey {
                e: e,
                n: n,
            }
        }
    }

    pub fn encrypt(&self, message: &Mpz) -> Mpz {
        encrypt(&self.public, message)
    }

    pub fn decrypt(&self, message: &Mpz) -> Mpz {
        decrypt(&self.private, message)
    }
}

pub fn encrypt(key: &PublicKey, message: &Mpz) -> Mpz {
    message.powm(&key.e, &key.n)
}

pub fn decrypt(key: &PrivateKey, message: &Mpz) -> Mpz {
    message.powm(&key.d, &key.n)
}


#[cfg(test)]
mod tests {
    use super::{from,KeyPair,PrivateKey,PublicKey};
    #[test]
    fn known_results() {
        // taken from
        // http://code.activestate.com/recipes/578838-rsa-a-simple-and-easy-to-read-implementation/
        let keypair = KeyPair {
            private: PrivateKey {
                n: from(2534665157),
                d: from(1810402843),
            },
            public: PublicKey {
                n: from(2534665157),
                e: from(7),
            },
        };

        assert_eq!(from(2463995467), keypair.encrypt(&from(123)));
        assert_eq!(from(2022084991), keypair.encrypt(&from(456)));
        assert_eq!(from(1299565302), keypair.encrypt(&from(123456)));

        assert_eq!(from(123), keypair.decrypt(&from(2463995467)));
        assert_eq!(from(456), keypair.decrypt(&from(2022084991)));
        assert_eq!(from(123456), keypair.decrypt(&from(1299565302)));
    }
}
