## Diffie-Hellman key exchange implementation

<span style="font-size:1.25em;">In order to insure encrypted communication in our application, we followed the Diffie-Hellman algorithim to implement a method for secure key exchange between two parties. This algorithim is the best method for two parties to be able to secretly share a symmetric key over a communication channel that isn't secure. In the end, this leads to each party possessing a simular shared secret without anyone else being able to determine what the secret key is. This solves one of the biggest problems in cryptography i.e., the key exchange problem.</span>

<span style="font-size:1.25em;">With Diffie-Hellman, the two parties must first agree on two parameters they are going to use. A value **g** called a generator, and value **p** which typically is a very large prime number. Each party will then select a secret value **a** and **b** that they keep private from anyone else. This secret value is used to calculate a public key which they can then exchange with each other openly.</span>

<span style="font-size:1.25em;"> By using the public key that was given from the other recipent, they can then combine with initially agreed values of **g** and **p** to calculate a third value, known only to the two parties. This third value is the Diffie-Hellman Shared Secret key.</span>

<span style="font-size:1.25em;"> Once the shared symmetric key is established, each party can then securly communicate over a public channel by exchanging encrypted data between each other that only the two parties sharing the same private key can decrypt. This essentially creates a secure channel for two parties to safely exchange secret information.</span>

<span style="font-size:1.25em;"> To acheive this we followed the same algorithim listed in RFC 2361 paper to generate the keys, while using the perscribed values listed in RFC 3526. For this assignment we used the 1536-bit MODP Group for both the prime number **p** and generator **g**</span>
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
670C354E 4ABC9804 F1746C08 CA237327 FFFFFFFF FFFFFFFF"""
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
## Integrity

<span style="font-size:1.25em;">We ensure integrity through the use of MACs or Message Authentication Codes. MACs allows us to verify knowledge without revealing details. Assuming that communications is captured, the MAC should not expose underlying information about our plain text data.</span>

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
        raise ValueError("Hashes didn't match buddddy")
    else:
        print("Hashes are a match! Message wasn't tampered with. OR WAS IT?")

```
<span style="font-size:1.25em;">On the receiver side within the "recv" function, we calculate the hashcode with the decrypted message and the shared key as inputs. If the hashes match, we can continue knowing the integrity of the message has not be compromised. Otherwise we raise a ValueError as it indicates the message has been tampered with.</span>

## Whatever?
