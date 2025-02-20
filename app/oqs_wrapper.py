from oqs import Signature

def generate_dilithium_keypair():
    sig = Signature("Dilithium5")
    public_key = sig.generate_keypair()
    private_key = sig.export_secret_key()
    return public_key.hex(), private_key.hex()