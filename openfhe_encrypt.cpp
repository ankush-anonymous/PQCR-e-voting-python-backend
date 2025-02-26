#include "openfhe.h"
#include <iostream>
#include <fstream>

using namespace lbcrypto;

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "Error: Candidate ID required as an argument." << std::endl;
        return 1;
    }

    // Initialize OpenFHE context for BFV encryption
    CryptoContext<DCRTPoly> cc = CryptoContextFactory<DCRTPoly>::genCryptoContextBFV(
        4096, 65537, HEStd_128_classic);
    
    cc->Enable(ENCRYPTION);
    cc->Enable(SHE);

    // Generate encryption keys
    auto keys = cc->KeyGen();
    cc->EvalMultKeyGen(keys.secretKey);

    // Convert candidate ID to integer
    int candidate_id = std::stoi(argv[1]);

    // Encrypt candidate ID
    Plaintext plaintext = cc->MakeIntegerPlaintext(candidate_id);
    auto ciphertext = cc->Encrypt(keys.publicKey, plaintext);

    // Serialize encrypted vote
    std::ofstream out("encrypted_vote.txt", std::ios::binary);
    if (!out) {
        std::cerr << "Error: Failed to open file for writing." << std::endl;
        return 1;
    }
    ciphertext->Serialize(out);
    out.close();

    // Output encrypted data as confirmation
    std::cout << "Vote encrypted and saved successfully." << std::endl;

    return 0;
}
