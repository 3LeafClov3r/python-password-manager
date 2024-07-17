from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import pandas as pd
import hashlib


df = pd.DataFrame(pd.read_csv('encryptedinfo/pswd.csv'))
# USR,EMAIL,PSWD,URL,TAGS,ROWHASH
user = "user"
email = "email@example.com"
password = "password"
URL = "https://example.com/login"
TAGS = "[Banking, Gaming]"
salt = "salt"
stringex = (user + email + password + URL + TAGS + salt).encode(encoding="utf-8")
print(stringex)
hash = hashlib.sha256()
hash.update(stringex)
new_row = {'USR': user, 'EMAIL': email, 'PSWD': password, 'URL': URL, 'TAGS': TAGS, 'SALT': "salt"}

df.loc[len(df)] = new_row
df.to_csv('encryptedinfo/pswd.csv', index=False)

# df = pd.DataFrame(pd.read_csv('encryptedinfo/pswd.csv'))
# print(df)

m = hashlib.sha256()
m.update(b"a")
print(m.hexdigest())



obj = AES.new(b'This is a key123', AES.MODE_CBC, b'This is an IV456')
message = b"The answer is no"
ciphertext = obj.encrypt(message)
print(ciphertext)
obj2 = AES.new(b'This is a key123', AES.MODE_CBC, b'This is an IV456')
print(obj2.decrypt(ciphertext))