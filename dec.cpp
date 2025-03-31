#include <openfhe.h>
using namespace lbcrypto;

int main() {
    CryptoContext<DCRTPoly> cc;
    PublicKey<DCRTPoly> publicKey;
    PrivateKey<DCRTPoly> privateKey;
    Ciphertext<DCRTPoly> singleVote;

    // Deserialize CryptoContext and keys (as in your original code)
    Serial::DeserializeFromFile("crypto_context.bin", cc, SerType::BINARY);
    Serial::DeserializeFromFile("public_key.bin", publicKey, SerType::BINARY);
    Serial::DeserializeFromFile("private_key.bin", privateKey, SerType::BINARY);

    // Load a single vote
    string singleVoteFile = "encrypted_votes/mumbai-election-9d8bfb27_3c838470-894e-45a0-986c-9a3d9d6e7d65_encrypted_vote.bin";
    if (!Serial::DeserializeFromFile(singleVoteFile, singleVote, SerType::BINARY)) {
        cerr << "Failed to deserialize single vote" << endl;
        return 1;
    }

    // Attempt decryption
    Plaintext result;
    try {
        cc->Decrypt(privateKey, singleVote, &result);
        cout << "Decrypted single vote: " << result->GetIntegerVector() << endl;
    } catch (const exception& e) {
        cerr << "Single vote decryption failed: " << e.what() << endl;
        return 1;
    }
    return 0;
}