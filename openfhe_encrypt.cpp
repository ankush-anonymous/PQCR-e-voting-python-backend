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
    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetPlaintextModulus(65537);
    parameters.SetMultiplicativeDepth(5);
    parameters.SetSecurityLevel(HEStd_128_classic);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);

    cc->Enable(PKESchemeFeature::PKE);
    cc->Enable(PKESchemeFeature::LEVELEDSHE);

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

    // Serialize without checking return (Serialize() is void)
    Serial::Serialize(ciphertext, out, SerType::BINARY);
    out.close();

    // Output confirmation
    std::cout << "Vote encrypted and saved successfully." << std::endl;

    return 0;
}
