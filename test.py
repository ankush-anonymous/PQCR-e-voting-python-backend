from oqs import Signature, get_enabled_sig_mechanisms

# List supported signature mechanisms
print("Supported signature mechanisms:", get_enabled_sig_mechanisms())

# Test Dilithium5
sig = Signature("Dilithium5")
public_key = sig.generate_keypair()
private_key = sig.export_secret_key()
print("Public Key:", public_key.hex())
print("Private Key:", private_key.hex())
