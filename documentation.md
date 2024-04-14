## Key Exchange

<span style="font-size:1.25em;">In order to ensure encrypted communication in our application, we followed the Diffie-Hellman algorithim to implement a method for secure key exchange between two parties. This algorithim is the best method for two parties to be able to secretly share a symmetric key over a communication channel that isn't secure. In the end, this leads to each party possessing a simular shared secret without anyone else being able to determine what the shared secret is. This solves one of the biggest problems in cryptography i.e., the key exchange problem.</span>

<span style="font-size:1.25em;">In our code we generate two shared secrets. One for encryption purposes and one for hashing purposes. This should improve security by reducing a centralised point of failure from having a single key. Should one of the keys be compromised in some way, only one of the functions (encryption or hashing) should fail. In this case, the failure/key leak should be detectable and precautions can be taken.</span>

<span style="font-size:1.25em;">With Diffie-Hellman, the two parties must first agree on two parameters they are going to use. A value **g** called a generator, and value **p** which typically is a very large prime number. Each party will then select a secret value **a** and **b** that they keep private from anyone else. This secret value is used to calculate a public key which they can then exchange with each other openly.</span>

<span style="font-size:1.25em;"> By using the public key that was given from the other recipent, they can then combine with initially agreed values of **g** and **p** to calculate a third value, known only to the two parties. This third value is the Diffie-Hellman Shared Secret key.</span>

<span style="font-size:1.25em;"> Once the shared symmetric key is established, each party can then securely communicate over a public channel by exchanging encrypted data between each other that only the two parties sharing the same private key can decrypt. This essentially creates a secure channel for two parties to safely exchange secret information.</span>

<span style="font-size:1.25em;"> To achieve this we followed the same algorithim listed in RFC2361 to generate the keys, while using the perscribed values listed in RFC3526. For this assignment we used the 2048-bit MODP Group for both the prime number **p** and generator **g**. This MODP group should be suitable for our purposes as in section 8 of the document, they estimate the strength of using this particular modulus as between 110 and 160 bits. As we are aiming for a 128 bit strength encryption system, this should in theory make it suitable to balance between system strength and resource usage. </span>

- Prime number *p*
```python
# obtained from RFC 3526
raw_prime = """FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
      29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
      EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
      E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
      EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
      C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
      83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
      670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
      E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9
      DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510
      15728E5A 8AACAA68 FFFFFFFF FFFFFFFF"""
# Convert from the value supplied in the RFC to an integer
prime = read_hex(raw_prime)
```
- Generator *g* or primitive root of the selected prime number *p*. This is the smallest multiple of the set primitive roots of *p*.
``` python
generator = 2 # As per RFC 3526
```
- This function in the \_\_init\_\_.py is first used to calculate the shared public key:

```python
def create_dh_key() -> Tuple[int, int]:
    private_key = secrets.randbelow(prime - 2)          # Generate secret using python secrets 
    public_key = pow(generator, private_key, prime)     # Creates a Diffie-Hellman key
    
    return (public_key, private_key)       # Returns (public, private)
```
# Confidentiality

<span style="font-size:1.25em;">We encrypt our data to hide the contents of our messages. For our system we use AES to encrypt our information. This encryption method was chosen due to its status as a Federal Information Processing Standard as endorsed by NIST. This means the underlying algorithm behind its implementation should be mathematically strong and that it has undergone rigorous scrutiny/testing.</span>

<span style="font-size:1.25em;">The mode of operation that we chose is CBC (Cipher-Block Chaining) for this implentation. As we are running a botnet, it is possible that the connection from server to client may not be completely stable. CBC prevents errors from propgating beyond two blocks. In CBC, each block of plaintext is XOR'ed with the previous block of ciphertext (or the IV for the first block). This error propogation means that errors will only affect two blocks and can enhance reliability</span>

<span style="font-size:1.25em;">Additionally, since the botnet will have a central server, the central server must decrypt many messages. While encryption with CBC cannot be done in parallel, decryption can. This means that although the central server has more messages to decrypt, the time/resources required to decrypt is not as high if parallelisation was not allowed.</span>

<span style="font-size:1.25em;">Using the shared secret we obtained during the Diffie Hellman key exchange, we create a symetric key using the AES algorithim to encrypt and dcrypt protected data. The code below highlights how we establish confidentiality using AES CBC to encrypt and decrypt data transmition.</span>

```python
# For encryption
# Create the cipher object
cipher = AES.new(self.shared_secret[0], AES.MODE_CBC)
# Encrypt the data.                                      
data_to_send = cipher.encrypt(pad(data, AES.block_size))
```
```python
# For decryption
# create new cipher object based on received IV.
cipher = AES.new(self.shared_secret[0], AES.MODE_CBC, iv)

# Decrypt the data and unpad our data
plain_text = unpad(cipher.decrypt(ct), AES.block_size)
```
## Integrity

<span style="font-size:1.25em;">Since operation such as CBC only provide guarantees over the confidentiality of the message but not over its integrity. An attacker could try to modify a message in transit and hope the receiver still accepts it. We ensure integrity through the use of MACs or Message Authentication Codes. MACs allows us to verify knowledge without revealing details. Assuming that communications is captured, the MAC should not expose underlying information about our plain text data.</span>

<span style="font-size:1.25em;">MACs achieves this by mapping abritary length strings into fixed length strings. The hashing algorithm should ensure that unique strings should generate unique codes.</span>

<span style="font-size:1.25em;">Unlike hashes, MACs require a key. This is another reason that we favour MACs. As we are running a botnet, a highly illegal activity where being caught would lead to a jail sentence, we use a keyed hashing to provide better security and to also allow authentication in addition to data integrity. We do note, however this is more resource intensive than non-keyed hashing, but the extra security should be worthwhile.</span>

<span style="font-size:1.25em;">The MAC framework we choose is HMAC, we choose this over secret suffix, secret prefix and envelope frameworks as HMAC has superior security and isn't weakn to birthday attacks or to length attacks and so on.</span>

```python
# Create the hmac hash using key and plaintext data # Task 3
hashcode = self.hmac_sha256(self.shared_secret[1], data)
    # Create the dictionary to send
dict_to_send = {'nonce':nonce, 'ciphertext':data_to_send, 'hash':hashcode}
```
<span style="font-size:1.25em;">Within the "send" function of the "comms.py" file, we have the above line. This uses a hashing framework, HMAC, and a hashing algorithm SHA-256 to securely hash our message. The input to this is our second secret shared key and the plain text data. The output is our hash code which is packed into a dictionary and sent with our encrypted message.</span>

```python
# Create the hashcode to check against the received hashcode # Task 3
hashcode_check = self.hmac_sha256(self.shared_secret[1], original_msg)

if hashcode_check != hashcode:
    raise ValueError("Hashes didn't match, Reject Message")
else:
    print("Hashes are a match! Message integrity confirmed.")

```
<span style="font-size:1.25em;">On the receiver side within the "recv" function, we calculate the hashcode with the decrypted message and the shared key as inputs. If the hashes match, we can continue knowing the integrity of the message has not be compromised. Otherwise we raise a ValueError as it indicates the message has been tampered with.</span>

## Replay Prevention

<span style="font-size:1.25em;">Replay is when an attacker tries to resend/retransmit a message, hoping the system still accepts the message. We counter this with the use of a nonce. A nonce is short for number-used-once. It is a random number appended to the message.</span>

```python
# Task 2
# Create Nonce with 64 bits of randomness
nonce = get_random_bytes(16)

# Check if the nonce is already in the set, if it is, generate a new one.
while nonce in self.nonce_set:
    nonce = get_random_bytes(16)
    print("Nonce already in set. Generating new nonce.")
else:    
    self.nonce_set.add(nonce)
    print(nonce, 'nonce not found in existing set. Adding to set.')

# Create the dictionary to send
dict_to_send = {'nonce':nonce, 'ciphertext':data_to_send, 'hash':hashcode}
```
<span style="font-size:1.25em;">The code above is taken from "comms.py" within the "send" function where we implement a nonce creator/checker. In the creation of a AES cipher object, we also create a nonce. We use a while loop to continually generate new nonces, checking for duplicates in our set until we generate a non duplicate. Once this occurs, we can encrypt our message with the cipher object and the associated nonce. If a duplicate is created, we simply generate another nonce.</span>

<span style="font-size:1.25em;">Since the nonce is 64 bits we have 2^64 possibilities. So we could generate a million nonces a second for 100 years and not run out of space.</span>

```python
# Extract the nonce and the ciphertext
nonce = b64['nonce']
if nonce in self.nonce_set:
    print(nonce, 'nonce found in existing set. Discarding message.')
    raise ValueError("Nonce was found in the set. Ending connection.")
else:
    print(nonce, 'nonce not found in existing set. Adding to set. Message is not a replay attack.')
```

<span style="font-size:1.25em;">In the "recv" function we implement a nonce checker, this will be where we detect replay attacks. We extract the nonce from the dictionary and the reciever checks the nonce against a set of existing nonces. If a message has a nonce that already exists in the set, this indicates that the message may be a replay attack. However, if the nonce is unique, we add it to the set, indicating it is a "seen nonce"</span>

## Authentication 
<span style="font-size:1.25em;">Allowing peer-to-peer (P2P) file transfers between bots in a botnet can serve several purposes that may be desirable for certain types of scenarios. These bots may use digital signatures so that only someone with access to the private key can control the botnet</span>

* <span style="font-size:1.25em;">**Anonymity:** Implementing P2P communication between bots, can provide a level of anonymity for file transfers to occur. Unlike centralized communication through a server, having P2P transfers will make it more challenging for an adversory to trace back to the originator. This enhances the botnet's stealth capabilities.
</span>

* <span style="font-size:1.25em;">**Scalability:** A P2P architecture can actualy scale more efficiently than relying on a central server using a client-server model to distribute files. As the size of the botnet grows, the burden on the central server increases, potentially leading to performance issues. Since "bots" or "zombies" can be remotely controlled by a command and control (C&C) server, P2P file transfers distribute the workload among multiple bots, allowing for better scalability.</span>

* <span style="font-size:1.25em;">**Redunancy:** P2P file transfers between bots can also provide redundancy in file distribution. If one bot is unavailable or compromised, other bots can take its place and still distribute files among others. This enhances  resilience in the network. </span>

* <span style="font-size:1.25em;">**Improved Network Topology:** P2P networks can dynamically adapt to changes in network topology more effectively than centralized systems. P2P bots perform as both a command distribution server and a client which receives commands. This way bots can join and leave the network dynamically without relying on a single point of failure.</span>

<span style="font-size:1.25em;">Having a centralised web server to controll the distribution of files in a botnet has its own advantages</span>

* <span style="font-size:1.25em;">**Increased Security:** Having a centralized file distribution can be more secure than P2P transfers, since access controls and encryption can be more easily enforced on a central server. This reduces the risk of unauthorized access to sensitive files</span>

* <span style="font-size:1.25em;">**Reliability:** A centralised server can offer higher reliability and availability compared to P2P file transfers. P2P can be subject to connectivity issues or bottlenecks among individual bots.</span>

* <span style="font-size:1.25em;">**Control:** A central web server provides centralized control over file distribution. The botnet operator can easily manage and monitor the files being distributed, ensuring that only authorized content is distrubuted.</span>

* <span style="font-size:1.25em;">**Logging and Auditing:** A Centralized server controlling file distribution can facilitate logging and auditing of file transfers. This providing a clear record of which files were distributed, when, and to whom. This can be valuable in situations where forensic analysis is needed.</span>

<span style="font-size:1.25em;">A central server managing communication between bots in a botnet can be vulnerable to attacks by different agencies in a number of ways. The implementation for bot-server communication has no safe guard against unauthorised access and verifing the other party we are performing the Diffie Hellman exchange is actually the person they claim to be. For this reason the key exchange would normally be implemented along side some form of authentication. This can include the following:</spans

- <span style="font-size:1.25em;">Public Key Infrastructure (PKI) Authentication: This involves the use of digital certificates issued by a trusted Certificate Authority (CA) to authenticate the identities of the communicating parties. Each party's public key is embedded in their certificate, which is signed by the CA.</span>
- <span style="font-size:1.25em;">Digital Signatures: After the Diffie-Hellman key exchange, each party can digitally sign a message. The recipient can verify the signature providing authentication</span>

<span style="font-size:1.25em;">While Diffie-Hellman itself doesn't provide authentication, it can be combined with other cryptographic techniques or protocols to achieve secure authentication during the key exchange process. For instance, if there was some way for the parties involved could securely communicate before hand and pre share their public keys like in RSA key exchange; they can verify every communication with a digital signature verifying there identify. This is why in modern forms hybrid techniques of encryption is usually implemented</span>

