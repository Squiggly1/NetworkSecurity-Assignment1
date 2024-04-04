from typing import Tuple
from Crypto.Hash import SHA256
from lib.helpers import read_hex
from random import randrange
from Crypto.Util import number

# Project TODO: Is this the best choice of prime? Why? Why not? Feel free to replace this!

# 1536 bit safe prime for Diffie-Hellman key exchange
# obtained from RFC 3526
raw_prime = """FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
670C354E 4ABC9804 F1746C08 CA237327 FFFFFFFF FFFFFFFF"""
# Convert from the value supplied in the RFC to an integer
prime = read_hex(raw_prime)

generator = 2 # As per RFC 3526

# Project TODO: Implement this function!
# Done, see below. priv = private key, pub = public key.
# Generated as per rfc2631 2.2 Key Generation.
# Task 1
def create_dh_key() -> Tuple[int, int]:
    # Creates a Diffie-Hellman key
    
    priv = randrange(1, prime-2)

    pub = pow(generator, priv, prime)

    # Returns (public, private)
    return (pub, priv)


def calculate_dh_secret(their_public: int, my_private: int) -> bytes:
    # Calculate the shared secret
    shared_secret = pow(their_public, my_private, prime)  # as per rfc2631.

    # Hash the value so that:
    # (a) There's no bias in the bits of the output
    #     (there may be bias if the shared secret is used raw)
    # (b) We can convert to raw bytes easily
    # (c) We could add additional information if we wanted
    # Feel free to change SHA256 to a different value if more appropriate
    shared_hash = SHA256.new(str(shared_secret).encode()).digest()
    return shared_hash

def rsa_keygen(e: int) -> Tuple[int, int, int]:
    
    # Select the public key, NIST specifies 2**16 > e >  2**256. 
    

    # Generate two large prime numbers (should be the same bit length)
    q = number.getPrime(2048)
    p = number.getPrime(2048)

    # Calculate n, the modulus for the public and private keys
    n = p * q

    # If certain conditions (outlined in NIST.FIPS.186-5 5.1 RSA Key Pair Generation)
    # are not met, regenerate the primes until they are met.
    while abs(q - p) < pow(2,100) and len(bin(n)) % 2 == 0 and len(bin(n)) > 2**2048:
        q = number.getPrime(2048)
        p = number.getPrime(2048)
        n = p * q
    """The same standard outlines how to prove primes, i'm not going to do that here. I'll assume that
    the pycryptodome function to generate primes can generate provable primes."""
    
    # Calculate the totient of n
    phi = (p - 1) * (q - 1)

    # Calculate the private key
    d = pow(e, -1, phi)

    return n, d