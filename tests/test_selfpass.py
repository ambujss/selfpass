import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import selfpass
from nose import with_setup
import string, random

PLAINTEXT_FILE = "ptext.txt"
CIPHERTEXT_FILE = "ctext.txt"

def _gen_random_string(length):
    return ''.join(random.choice(string.ascii_uppercase + \
                                 string.digits + \
                                 string.ascii_lowercase + \
                                 string.punctuation + " ") for _ in range(length))

def remove_files(files):
    for f in files:
        if os.path.exists(f):
            os.remove(f)

def fsetup():
    global PLAINTEXT_FILE, CIPHERTEXT_FILE
    remove_files([PLAINTEXT_FILE, CIPHERTEXT_FILE])
    with open(PLAINTEXT_FILE, "w") as f:
        f.write(_gen_random_string(1000))

def ftdown():
    global PLAINTEXT_FILE, CIPHERTEXT_FILE
    remove_files([PLAINTEXT_FILE, CIPHERTEXT_FILE])

@with_setup(fsetup, ftdown)
def test_file_cipher_encryption_mode():
    filecipher = selfpass.FileCipher()
    with open(PLAINTEXT_FILE) as f:
        plaintext = f.read()
    filecipher.set_src(PLAINTEXT_FILE)
    filecipher.set_dst(CIPHERTEXT_FILE)

    password =_gen_random_string(selfpass.MIN_PASS_LEN)
    filecipher.set_password(password)
    filecipher.set_mode_to_encode()

    assert filecipher.is_processed() == False, "File Cipher is processed before processing!"

    # Process File Cipher
    filecipher.process()
    ciphertext = filecipher.get_ciphertext()
    assert plaintext != ciphertext, "Plaintext and ciphertext are same! " \
        "ctext: %s, ptext: %s"%(ciphertext, plaintext)

    assert filecipher.is_processed() == True, "File Cipher is not processed after processing!"

    # commit ciphertext to file
    filecipher.commit()
    with open(CIPHERTEXT_FILE) as cf:
        fciphertext = cf.read()
    assert fciphertext == ciphertext, "Cipher text commited to file different from computed ciphertext!"

    # Now reset and test decode mode
    filecipher.reset()

    filecipher.set_src(CIPHERTEXT_FILE)
    filecipher.set_dst(PLAINTEXT_FILE)
    filecipher.set_password(password)
    filecipher.set_mode_to_decode()

    assert filecipher.is_processed() == False, "File Cipher is processed before processing!"

    # Process File Cipher
    filecipher.process()
    decryptedtext = filecipher.get_plaintext()
    assert decryptedtext != ciphertext, "Decrypted text and ciphertext are same! " \
        "ctext: %s, dtext: %s"%(ciphertext, decryptedtext)
    assert decryptedtext == plaintext, "Decrypted text and plaintext are not same!"

    assert filecipher.is_processed() == True, "File Cipher is not processed after processing!"

    # commit ciphertext to file
    filecipher.commit()
    with open(PLAINTEXT_FILE) as pf:
        fplaintext = pf.read()
    assert fplaintext == plaintext, "Plain text commited to file different from decrypted text!"

