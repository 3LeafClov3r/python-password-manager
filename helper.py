from Crypto.Cipher import Salsa20
from Crypto.Random import get_random_bytes
import pandas as pd
from io import StringIO
import hashlib
from Crypto.Hash import HMAC, SHA256


def write_encrypted_file(df, secret_key, file_name):
    with open('encryptedinfo/' + file_name, 'wb') as f:
        cipher = Salsa20.new(key=secret_key)
        msg = cipher.nonce + cipher.encrypt(df.to_csv().encode('utf-8'))
        f.write(msg)
        print(f"csv; {df.to_csv()}")
        print(f"encoded: {df.to_csv().encode('utf-8')}")
        f.close()


def return_decrypted_dataframe(file_name, secret_key):
    with open('encryptedinfo/' + file_name, 'rb') as f:
        message = f.read()
        msg_nonce = message[:8]
        ciphertext = message[8:]
        cipher = Salsa20.new(key=secret_key, nonce=msg_nonce)
        plaintext1 = cipher.decrypt(ciphertext)
        ptext = plaintext1.decode('utf-8')
        f.close()
        return pd.read_csv(StringIO(ptext))

def generate_hash(msg, secret_key):
    h = HMAC.new(secret_key, digestmod=SHA256)
    h.update(msg)
    # print(h.hexdigest())
    return h.hexdigest()


def verify_hash(msg, secret_key, mac_hash):
    h = HMAC.new(secret_key, digestmod=SHA256)
    h.update(msg)
    try:
        h.hexverify(mac_hash)
        print("The message '%s' is authentic" % msg)
        return True
    except ValueError:
        print("The message or the key is wrong")
        return False

def change_encryption_key_and_re_encrypt(old_secret_key, new_secret_key):
    df = return_decrypted_dataframe("encrypted.bin", old_secret_key)
    write_encrypted_file(df, new_secret_key, "encrypted.bin")
