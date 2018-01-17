import cipherutils as cutils

MIN_PASS_LEN = 10

class IncorrectExecution(Exception): pass

class FileCipher(object):
    """
    Base class providing methods to encrypt and decrypt files.
    """
    def __init__(self, **kwargs):
        self.reset()

    def reset(self):
        self.src = None
        self.dst = None
        self.password = None

        self.plaintext = None
        self.ciphertext = None

        self.srctext = None
        self.dsttext = None

        self.encode_mode = True
        self._processed = False

    def is_processed(self):
        return self._processed

    def check_process_params(self):
        if self.src is None:
            raise IncorrectExecution("Source file not provided")
        if self.password is None:
            raise IncorrectExecution("Password not provided")

    def check_commit_params(self):
        if self.dst is None:
            raise IncorrectExecution("Destination file not provided.")
        if not self._processed:
            raise IncorrectExecution("Cipher has not been processed. Please call " \
                                     "process before commit.")
    def set_src(self, src):
        self.src = src

    def set_dst(self, dst):
        self.dst = dst

    def set_password(self, password):
        self.password_spec_check(password)
        self.password = password

    def get_plaintext(self):
        return self.plaintext

    def get_ciphertext(self):
        return self.ciphertext

    def set_mode_to_encode(self):
        self.encode_mode = True

    def set_mode_to_decode(self):
        self.encode_mode = False

    def password_spec_check(self, password):
        plen = len(password)
        if plen < MIN_PASS_LEN:
            raise ValueError("Password needs to be atleast %d charactersin length"%MIN_PASS_LEN)

    def process(self):
        self.check_process_params()
        with open(self.src) as sfile:
            self.srctext = sfile.read()
        if self.encode_mode:
            self.plaintext = self.srctext
            self.dsttext = cutils.encode_with_password(self.plaintext, self.password)
            self.ciphertext = self.dsttext
        else:
            self.ciphertext = self.srctext
            self.dsttext = cutils.decode_with_password(self.ciphertext, self.password)
            self.plaintext = self.dsttext
        self._processed = True

    def commit(self):
        self.check_commit_params()
        with open(self.dst, "w") as dfile:
            dfile.write(self.dsttext)
