from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

data = b'secret data'

key = get_random_bytes(16)

print(f"key: {key}")
cipher = AES.new(key, AES.MODE_EAX)

ciphertext, tag = cipher.encrypt_and_digest(data)
print(f"ciphertext = {ciphertext}")
nonce = cipher.nonce


cipher1 = AES.new(key, AES.MODE_EAX, nonce)

data = cipher1.decrypt_and_verify(ciphertext, tag)
print(data)