from Crypto.Cipher import Salsa20
import pandas as pd
import hashlib
from helper import return_decrypted_dataframe, write_encrypted_file, generate_hash, verify_hash
from Crypto.Hash import HMAC, SHA256


df = pd.DataFrame(pd.read_csv('encryptedinfo/pswd.csv'))
user = "user"
email = "email@example.com"
password = "password"
URL = "https://example.com/login"
TAGS = "[Banking, Gaming]"

# stringex = (user + email + password + URL + TAGS + salt).encode(encoding="utf-8")
# print(stringex)
# hash = hashlib.sha256()
# hash.update(stringex)
new_row = {'USR': user, 'EMAIL': email, 'PSWD': password, 'URL': URL, 'TAGS': TAGS}

# df.loc[len(df)] = new_row
# df.to_csv('encryptedinfo/pswd.csv', index=False)


# df = pd.DataFrame(pd.read_csv('encryptedinfo/pswd.csv'))
secret_key = b"*Thirty-two byte (256 bits) key*"
# write_encrypted_file(df, secret_key, "encrypted.bin")

# print(return_decrypted_dataframe("encrypted.bin", secret_key))
msg = df.to_csv().encode('utf-8')
hash_ = generate_hash(msg, secret_key)

verify_hash(msg, secret_key, hash_)




