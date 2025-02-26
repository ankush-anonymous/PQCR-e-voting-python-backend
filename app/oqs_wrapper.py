from oqs import Signature

class SignatureWrapper:
    def __init__(self, algorithm="Dilithium5", secret_key=None):
        self.sig = Signature(algorithm, secret_key)

    def generate_keypair(self):
        return self.sig.generate_keypair()

    def sign(self, message):
        return self.sig.sign(message)

    def verify(self, message, signature, public_key):
        return self.sig.verify(message, signature, public_key)

    def export_secret_key(self):
        return self.sig.export_secret_key()
