import pickle

import struct
import secrets

from dh import create_dh_key, calculate_dh_secret, rsa_keygen
from Crypto.Cipher import AES

from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15

from Crypto.Hash import SHA256
from lib.helpers import appendMac, macCheck, appendSalt, generate_random_string

from typing import Tuple
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA512


class StealthConn(object):
    def __init__(self, conn, client=False, server=False, verbose=False):
        self.conn = conn
        self.client = client
        self.server = server
        self.verbose = True  # verbose
        self.shared_secret = []
        self.initiate_session()
        # Disable authentication for now
        self.nonce_set = set()

    def initiate_session(self):
        # Perform the initial connection handshake for agreeing on a shared secret

        # This can be broken into code run just on the server or just on the client
        if self.server or self.client:
            for i in range(2):
                print(i, 'i')
                my_public_key, my_private_key = create_dh_key()
                
                # Send them our public key
                self.send(bytes(str(my_public_key), "ascii"))
                
                # Receive their public key
                their_public_key = int(self.recv())
                
                # Obtain our shared secret
                self.shared_secret.append(calculate_dh_secret(their_public_key, my_private_key))
                print("Shared first hash: {}".format(self.shared_secret))
            # Disable this below part, as it's not needed for the assignment.
            """e = 65537
            n, d = rsa_keygen(e)
            self.rsa_private_key = RSA.construct((n, e, d))
            self.rsa_public_key = RSA.construct((n, e))"""

    def send(self, data: bytes):

        # If we have not generated 2 shared secrets, do not encrypt the data, just send it
        if len(self.shared_secret) == 2:
            # Encrypt the message
            # Project TODO: Is XOR the best cipher here? Why not? Use a more secure cipher (from the pycryptodome library)

            # Modify XOR to AES CTR mode.
            # Task 2
            cipher = AES.new(self.shared_secret[0], AES.MODE_CTR)

            # Create Nonce, in this case, automatically generated.
            nonce = cipher.nonce

            # Check if the nonce is already in the set, if it is, generate a new one.
            while nonce in self.nonce_set:
                cipher = AES.new(self.shared_secret[0], AES.MODE_CTR)
                nonce = cipher.nonce
            else:    
                self.nonce_set.add(nonce)
            
                print(nonce, 'nonce not found in existing set. Adding to set.')
                        
            # Encrypt the data with the successful nonce.
            data_to_send = cipher.encrypt(data)
            
            # Create the hmac hash using key and plaintext data # Task 3
            hashcode = self.hmac_sha256(self.shared_secret[1], data)

            # Create the dictionary to send
            dict_to_send = {'nonce':nonce, 'ciphertext':data_to_send, 'hash':hashcode}

            # pickle the dictionary so that it can be sent using python socket.sendall()
            dict_to_send = pickle.dumps(dict_to_send)

            # Task 4 Signature
            # signature = pkcs1_15.new(self.rsa_private_key).sign(SHA256.new(data))

            if self.verbose:
                print()
                print("Original message : {}".format(data))
                print("Encrypted data: {}".format(repr(dict_to_send)))
                print("Sending packet of length: {}".format(len(dict_to_send)))
                print()
        else:
            dict_to_send = data


        # Sending the data is contained below
        # Encode the data's length into an unsigned two byte int ('H')
        pkt_len = struct.pack("H", len(dict_to_send))
        self.conn.sendall(pkt_len)
        self.conn.sendall(dict_to_send)


    def recv(self):
        # Decode the data's length from an unsigned two byte int ('H')
        pkt_len_packed = self.conn.recv(struct.calcsize("H")) # 
        unpacked_contents = struct.unpack("H", pkt_len_packed) # 
        pkt_len = unpacked_contents[0] # 

        if len(self.shared_secret) == 2:
            try:
                encrypted_data = self.conn.recv(pkt_len)
                # Project TODO: as in send(), change the cipher here.

                # Task 2
                
                # Unpickle the dictionary
                b64 = pickle.loads(encrypted_data)

                # Extract the nonce and the ciphertext
                nonce = b64['nonce']
                if nonce in self.nonce_set:
                    print(nonce, 'nonce found in existing set. Discarding message.')
                    raise ValueError("Nonce was found in the set. Ending connection.")
                else:
                    print(nonce, 'nonce not found in existing set. Adding to set. Message is not a replay attack.')

                ct = b64['ciphertext']
                hashcode = b64['hash']
                
                # create new cipher object based on received nonce.
                cipher = AES.new(self.shared_secret[0], AES.MODE_CTR, nonce=nonce)

                # Decrypt the data
                original_msg = cipher.decrypt(ct)

                # Create the hashcode to check against the received hashcode # Task 3
                hashcode_check = self.hmac_sha256(self.shared_secret[1], original_msg)

                if hashcode_check != hashcode:
                    raise ValueError("Hashes didn't match buddddy")
                else:
                    print("Hashes are a match! Message wasn't tampered with. OR WAS IT?")

                if self.verbose:
                    print()
                    print("Receiving message of length: {}".format(len(encrypted_data)))
                    print("Encrypted data: {}".format(repr(encrypted_data)))
                    print("Original message: {}".format(original_msg))
                    print()
            except (ValueError, KeyError):

                print("Incorrect decryption or Hashes do not match")   

        else:
            original_msg = self.conn.recv(pkt_len)

        return original_msg

    def close(self):
        self.conn.close()

    # Based on specification RFC 2104
    def hmac_sha256(self, key: bytes, message: bytes) -> bytes:
        ipad = 0x36
        opad = 0x5C
        block_length = 64
        # If the key is longer than the block size, hash it so it's reduced to the block size
        # Note that this assumes key is in bytes
        if len(key) > block_length:

            # digest() instead of hexdigest() to get bytes instead of hexadecimals
            key = SHA256.new(key).digest()

        # If the key is shorter than the block size, pad it with zeros
        if len(key) < 64:
            key = key + (b'\x00' * (block_length - len(key)))

        # XOR the key with the inner pad value
        inner_pad = bytes([x ^ ipad for x in key])
        
        # Append the message to the inner pad
        inner_append_message = inner_pad + message

        # Hash the inner operation
        inner_hash = SHA256.new(inner_append_message).digest()

        # XOR the key with the outer pad value
        outer_pad = bytes([x ^ opad for x in key])

        # Append the hashed inner operation to the outer pad
        outer_append_message = outer_pad + inner_hash

        # Hash the outer operation
        outer_hash = SHA256.new(outer_append_message).digest()

        # Return the HMAC
        return outer_hash
    
    def key_derivation(shared_secret):

        master_secret = get_random_bytes(32)
        
        key1, key2 = HKDF(master=master_secret, key_len=32, hashmod=SHA512, )

        print(key1,key2)

        return encryption_key

    """Ignore below code, not used."""

    def rsa_signature(self, message: bytes, private_key: Tuple[int, int]) -> Tuple[bytes, Tuple[int, int]]:

        nonce = secrets.token_bytes(32) # 256 bit key

        self.nonce_set.add(nonce)

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
