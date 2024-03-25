import pickle

import struct


from dh import create_dh_key, calculate_dh_secret
from Crypto.Cipher import AES
from lib.helpers import appendMac, macCheck, appendSalt, generate_random_string


class StealthConn(object):
    def __init__(self, conn, client=False, server=False, verbose=False):
        self.conn = conn
        self.client = client
        self.server = server
        self.verbose = True  # verbose
        self.shared_secret = None
        self.initiate_session()

    def initiate_session(self):
        # Perform the initial connection handshake for agreeing on a shared secret

        # This can be broken into code run just on the server or just on the client
        if self.server or self.client:
            my_public_key, my_private_key = create_dh_key()
            # Send them our public key
            self.send(bytes(str(my_public_key), "ascii"))
            # Receive their public key
            their_public_key = int(self.recv())
            # Obtain our shared secret
            self.shared_secret = calculate_dh_secret(their_public_key, my_private_key)
            print("Shared hash: {}".format(self.shared_secret.hex()))

    def send(self, data):
        if self.shared_secret:
            # Encrypt the message
            # Project TODO: Is XOR the best cipher here? Why not? Use a more secure cipher (from the pycryptodome library)

            # Modify XOR to AES CTR mode.
            cipher = AES.new(self.shared_secret, AES.MODE_CTR)

            

            # Encrypt the data 
            data_to_send = cipher.encrypt(data)
            
            # Create Nonce, in this case, automatically generated.
            nonce = cipher.nonce

            # Create the dictionary to send
            dict_to_send = {'nonce':nonce, 'ciphertext':data_to_send}

            # pickle the dictionary
            dict_to_send = pickle.dumps(dict_to_send)


            if self.verbose:
                print()
                print("Original message : {}".format(data))
                print("Encrypted data: {}".format(repr(dict_to_send)))
                print("Sending packet of length: {}".format(len(dict_to_send)))
                print()
        else:
            dict_to_send = data

        # Encode the data's length into an unsigned two byte int ('H')

        pkt_len = struct.pack("H", len(dict_to_send)) 

        self.conn.sendall(pkt_len) # 
        self.conn.sendall(dict_to_send) # 

    def recv(self):
        # Decode the data's length from an unsigned two byte int ('H')
        pkt_len_packed = self.conn.recv(struct.calcsize("H")) # 
        unpacked_contents = struct.unpack("H", pkt_len_packed) # 

        pkt_len = unpacked_contents[0] # 

        if self.shared_secret:
            try:

                encrypted_data = self.conn.recv(pkt_len)
                # Project TODO: as in send(), change the cipher here.

                # Changed cipher to AES, just like recieved data.

                b64 = pickle.loads(encrypted_data)

                nonce = b64['nonce']
                ct = b64['ciphertext']
                
                cipher = AES.new(self.shared_secret, AES.MODE_CTR, nonce=nonce)

                original_msg = cipher.decrypt(ct)

                if self.verbose:
                    print()
                    print("Receiving message of length: {}".format(len(encrypted_data)))
                    print("Encrypted data: {}".format(repr(encrypted_data)))
                    print("Original message: {}".format(original_msg))
                    print()
            except (ValueError, KeyError):

                print("Incorrect decryption")   

        else:
            original_msg = self.conn.recv(pkt_len)

        return original_msg

    def close(self):
        self.conn.close()
