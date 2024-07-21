import pandas as pd
import hashlib
from helper import *
import io
import streamlit as st

df = pd.DataFrame(pd.read_csv(io.StringIO('encryptedinfo/pswd.csv')))
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
new_secret_key = b"*Thirty-two byte (256 bits) keyy"
# write_encrypted_file(df, secret_key, "encrypted.bin")
# change_encryption_key_and_re_encrypt(secret_key, new_secret_key)


print(df)
dataframe = return_decrypted_dataframe("encrypted.bin", new_secret_key)
print(dataframe)
dataframe.to_csv("encryptedinfo/pswd.csv", index = False)

# write_encrypted_file(df, new_secret_key,"encrypted.bin")

# print(return_decrypted_dataframe("encrypted.bin", secret_key))

# msg = df.to_csv().encode('utf-8')
# hash_ = generate_hash(msg, secret_key)
#
# verify_hash(msg, secret_key, hash_)




