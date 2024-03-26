from Crypto.Hash import SHA256

#Naive implementation of HMAC
import secrets
randomkey = secrets.token_bytes(32) # 256 bit key
message = (b"Lorem ipsum dolor sit amet, consectetur adipiscing elit, "
           b"sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. "
           b"Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris "
           b"nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in "
           b"reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. "
           b"Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia "
           b"deserunt mollit anim id est laborum.")

print(type(randomkey))
# data type is

def hmac_sha256(key, message):
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

output = hmac_sha256(randomkey, message)
print(output.hex(),'hmac_sha256')