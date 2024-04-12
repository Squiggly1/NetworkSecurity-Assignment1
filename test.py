from Crypto.Cipher import AES
import random
from Crypto.Random import get_random_bytes

shared_secret = get_random_bytes(16)


cipher = AES.new(shared_secret, AES.MODE_CBC)
nonce = cipher.nonce

print(nonce, 'nonce')