import os
import sys
import json
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import selfpass
from nose import with_setup
import string, random

PLAINTEXT_FILE = "ptext.txt"
CIPHERTEXT_FILE = "ctext.txt"

def _gen_random_string(length, special_chars=True):
    if special_chars:
        char_pool = string.ascii_uppercase + \
                    string.digits + \
                    string.ascii_lowercase + \
                    string.punctuation + " "
    else :
        char_pool = string.ascii_uppercase + \
                    string.digits + \
                    string.ascii_lowercase
    return ''.join(random.choice(char_pool) for _ in range(length))

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

## Other tests to add
#  - test for invalid password lengths
#  - attempt to get/set values when they are not get/settable

PASSWORD_FILE = "password.txt"

CONTEXT1 = _gen_random_string(12)
USER1 = _gen_random_string(10)
PASS1 = _gen_random_string(10)
USER1b = _gen_random_string(2)
PASS1b = _gen_random_string(3)

CONTEXT2 = _gen_random_string(12)
USER2 = _gen_random_string(10)
PASS2 = _gen_random_string(16)
PASS2b = _gen_random_string(12)

MASTER_PASS = None

PASSWORD_CORPUS = json.dumps({
    CONTEXT1 : {USER1  : {"password" : PASS1},
                USER1b : {"password" : PASS1b}
    },
    CONTEXT2 : {USER2  : {"password" : PASS2},
                USER1b : {"password" : PASS2b}
    },
})

# print "C1 = %s, U1 = %s, P1 = %s" % (CONTEXT1, USER1, PASS1)
# print "  U1b = %s, P1b = %s" % (USER1b, PASS1b)
# print "C2 = %s, U2 = %s, P2 = %s" % (CONTEXT2, USER2, PASS2)
# print "  U1b = %s, P2b = %s" % (USER1b, PASS2b)

def psetup():
    global PASSWORD_FILE, MASTER_PASS, PASSWORD_CORPUS
    MASTER_PASS = _gen_random_string(10)
    remove_files([PASSWORD_FILE])
    with open(PASSWORD_FILE, "w") as pf:
        import cipherutils as cutils
        pf.write(cutils.encode_with_password(PASSWORD_CORPUS, MASTER_PASS))

def ptdown():
    global PASSWORD_FILE, MASTER_PASS
    remove_files([PASSWORD_FILE])
    MASTER_PASS = None

@with_setup(psetup, ptdown)
def test_password_cipher():
    global PASSWORD_FILE, MASTER_PASS, USER1, USER2, PASS1, PASS2
    password = MASTER_PASS
    pcipher = selfpass.PasswordCipher(PASSWORD_FILE, password)

    contexts = pcipher.contexts()
    assert set(contexts) == set([CONTEXT1, CONTEXT2])

    creds = pcipher.get_credentials(context=CONTEXT1)
    for username, secret in creds.iteritems():
        if username == USER1:
            assert secret["password"] == PASS1, \
                "Password did not match for %s. expected %s, got %s" % (USER1, PASS1,
                                                                        secret["password"])
        elif username == USER1b:
            assert secret["password"] == PASS1b, \
                "Password did not match for %s. expected %s, got %s" % (USER1b, PASS1b,
                                                                        secret["password"])
        else:
            assert False, "Unknown username %s for context %s"%(username, CONTEXT1)

    creds = pcipher.get_credentials(context=CONTEXT2)
    for username, secret in creds.iteritems():
        if username == USER2:
            assert secret["password"] == PASS2, \
                "Password did not match for %s. expected %s, got %s" % (USER2, PASS2,
                                                                        secret["password"])
        elif username == USER1b:
            assert secret["password"] == PASS2b, \
                "Password did not match for %s. expected %s, got %s" % (USER1b, PASS2b,
                                                                        secret["password"])
        else:
            assert False, "Unknown username %s for context %s"%(username, CONTEXT2)

    # attempt to get creds of bad context
    assert None == pcipher.get_credentials(context=_gen_random_string(10))

    assert pcipher.get_password(context=CONTEXT1, username=USER1) == PASS1
    assert pcipher.get_password(context=CONTEXT1, username=USER1b) == PASS1b
    assert pcipher.get_password(context=CONTEXT2, username=USER2) == PASS2
    assert pcipher.get_password(context=CONTEXT2, username=USER1b) == PASS2b

    # test valid context, bad username
    assert pcipher.get_password(context=CONTEXT1, username=_gen_random_string(12)) == None

    # test bad context, valid username
    assert pcipher.get_password(context=_gen_random_string(12), username=USER1) == None

    # test valid context, valid username from different context
    assert pcipher.get_password(context=CONTEXT1, username=USER2) == None

    # test bad context, bad username
    assert None == pcipher.get_password(context=_gen_random_string(12),
                                        username=_gen_random_string(12))
