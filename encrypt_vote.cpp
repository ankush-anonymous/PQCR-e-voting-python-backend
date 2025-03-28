#include <openfhe.h>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <vector>
#include <string>

#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/bfvrns/bfvrns-ser.h"

using namespace lbcrypto;

void encryptVector(const std::string& electionId, const std::vector<int64_t>& oneHotVector) {
    try {
        // Construct file paths
        std::string folder = electionId + "_credentials/";
        std::string contextFile = folder + "cryptocontext.bin";
        std::string publicKeyFile = folder + "public_key.bin";
        std::string outputFilePath = folder + "encrypted_vector.bin";

        // Deserialize crypto context
        CryptoContext<DCRTPoly> cc;
        if (!Serial::DeserializeFromFile(contextFile, cc, SerType::BINARY)) {
            throw std::runtime_error("Failed to deserialize crypto context from " + contextFile);
        }

        // Enable necessary features (must match keygen)
        cc->Enable(PKE);
        cc->Enable(KEYSWITCH);
        cc->Enable(LEVELEDSHE);

        // Deserialize public key
        PublicKey<DCRTPoly> publicKey;
        if (!Serial::DeserializeFromFile(publicKeyFile, publicKey, SerType::BINARY)) {
            throw std::runtime_error("Failed to deserialize public key from " + publicKeyFile);
        }

        // Encrypt the one-hot vector
        Plaintext plaintext = cc->MakeCoefPackedPlaintext(oneHotVector);
        Ciphertext<DCRTPoly> ciphertext = cc->Encrypt(publicKey, plaintext);
        if (!ciphertext) {
            throw std::runtime_error("Failed to encrypt the vector");
        }

        // Serialize and save the ciphertext
        if (!Serial::SerializeToFile(outputFilePath, ciphertext, SerType::BINARY)) {
            throw std::runtime_error("Failed to serialize ciphertext to " + outputFilePath);
        }
        std::cout << "Vector encrypted and saved to " << outputFilePath << std::endl;

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        throw;
    }
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <election_id> <one_hot_vector_values...>" << std::endl;
        std::cerr << "Example: " << argv[0] << " ankush123 0 1 1" << std::endl;
        return 1;
    }

    std::string electionId = argv[1];
    std::vector<int64_t> oneHotVector;
    for (int i = 2; i < argc; ++i) {
        try {
            oneHotVector.push_back(std::stoll(argv[i]));
        } catch (const std::exception& e) {
            std::cerr << "Invalid vector value: " << argv[i] << std::endl;
            return 1;
        }
    }

    try {
        encryptVector(electionId, oneHotVector);
    } catch (const std::exception& e) {
        return 1;
    }
    return 0;
}