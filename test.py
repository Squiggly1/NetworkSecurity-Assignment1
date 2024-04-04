
q = "0x4000000000000000000020108A2E0CC0D99F8A5EF"
q_int = int(q, 16)  # Convert hexadecimal string to integer
bit_length = q_int.bit_length()  # Get bit length
print(bit_length)