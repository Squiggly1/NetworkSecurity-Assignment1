from Crypto.Hash import SHA256
from Crypto.Util import number
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15

from typing import Tuple


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



def rsa_signature(message: bytes, private_key: Tuple[int, int]) -> Tuple[bytes, Tuple[int, int]]:
    # Hash the message
    hashed_message = SHA256.new(message)

    # Set the key
    key = private_key

    # Sign the message
    signature = pkcs1_15.new(key).sign(hashed_message)

    return signature

def verify_signature(message: bytes, signature: bytes, public_key: Tuple[int, int]) -> bool:
    # Hash the message
    hashed_message = SHA256.new(message)

    # Set the key
    key = public_key

    # Verify the signature
    try:
        pkcs1_15.new(key).verify(hashed_message, signature)
        print("The signature is valid.")

    except (ValueError, TypeError):

        print("The signature is not valid.")

e = 65537
n, d = rsa_keygen(e)

private_key = RSA.construct((n, e, d))
public_key = RSA.construct((n, e))


msg = b"Hello, World!"
signature = rsa_signature(msg, private_key)

verify_signature(msg, signature, public_key)
