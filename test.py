import json

data_to_send = 'test'
nonce = 'nonce'


data_to_send = json.dumps({'nonce':nonce, 'ciphertext':data_to_send})
print(data_to_send)
data_to_send = bytes(data_to_send, 'utf-8')
print(data_to_send)
data_to_send = data_to_send.decode('utf-8')
print(data_to_send)