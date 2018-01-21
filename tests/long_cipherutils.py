import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import cipherutils as cutils
import random, string

## The tests in this file take very long to run. Hence I'm putting
## them in a separate manually run file.

def _gen_random_string(length):
    return ''.join(random.choice(string.ascii_uppercase + \
                                 string.digits + \
                                 string.ascii_lowercase + \
                                 string.punctuation + " ") for _ in range(length))

def _do_test(plaintext, password):
    ctext = cutils.encode_with_password(plaintext, password)
    # test that ciphertext is not plaintext
    assert ctext != plaintext, "Cipher text should be different from plaintext!" \
        " ctext: %s ptext: %s"%(ctext, ptext)

    # test that decrypted text is same as plaintext
    dtext = cutils.decode_with_password(ctext, password)
    assert dtext == plaintext, "Decrypted text is not same as plaintext!" \
        "dtext: %s, ptext: %s"%(dtext, ptext)

    # test that 2 instances of encryption with same plaintext and key
    # are not same
    ctext2 = cutils.encode_with_password(plaintext, password)
    assert ctext2 != ctext, "results of 2 different encryptions are same!"
    dtext2 = cutils.decode_with_password(ctext2, password)
    assert dtext2 == plaintext, "Decrypted text of secod encryption does not match plaintext!" \
        "dtext2: %s, ptext: %s"%(dtext2, ptext)

# Test encode and decode with a variety of password lengths
def test_encode_decode_with_diff_password_lengths():
    passlens = [0, 1, 16, 32, 50, 64, 100, 128, 200, 256]
    plaintext = _gen_random_string(100)
    for passlen in passlens:
        password  = _gen_random_string(passlen)
        _do_test(plaintext, password)

def test_encode_decode_with_diff_plaintext_lengths():
    ptextlens = [0, 1, 16, 32, 50, 64, 100, 256, 1000, 2500, 4132, 4096]
    password = _gen_random_string(10)
    for ptextlen in ptextlens:
        plaintext  = _gen_random_string(ptextlen)
        _do_test(plaintext, password)
