from nacl import secret
from nacl import utils
from nacl import encoding
from nacl import pwhash
import time

SALT_LEN = pwhash.argon2i.SALTBYTES

## Public API ##

def encode_with_password(plaintext, password):
    key, salt = _gen_key_and_salt(password)
    enc = _encrypt(plaintext, key)
    return salt + enc

def decode_with_password(ciphertext, password):
    salt, enc = _get_salt_and_enc(ciphertext)
    key = _get_key(password, salt)
    return _decrypt(enc, key)

## Private helpers ##

def _encrypt(msg, key):
    box = secret.SecretBox(key)
    return box.encrypt(msg)

def _decrypt(ciphertext, key):
    box = secret.SecretBox(key)
    return box.decrypt(ciphertext)

def _gen_key_and_salt(password):
    derivation_salt = utils.random(SALT_LEN)
    key = _get_key(password, derivation_salt)
    return key, derivation_salt

def _get_key(password, salt):
    kdf = pwhash.argon2i.kdf
    ops = pwhash.argon2i.OPSLIMIT_SENSITIVE
    mem = pwhash.argon2i.MEMLIMIT_SENSITIVE
    key = kdf(secret.SecretBox.KEY_SIZE, password, salt,
                 opslimit=ops, memlimit=mem)
    return key

def _get_salt_and_enc(ciphertext):
    return ciphertext[:SALT_LEN], ciphertext[SALT_LEN:]
