#include <openfhe.h>
#include <iostream>
#include <fstream>
#include <string>
#include <filesystem>

#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/bfvrns/bfvrns-ser.h"

using namespace lbcrypto;
using namespace std;
namespace fs = std::filesystem;

int main(int argc, char *argv[]) {
    // **Input Validation**
    if (argc != 2) {
        cerr << "Usage: " << argv[0] << " <election_id>" << endl;
        cerr << "Example: " << argv[0] << " election123" << endl;
        return 1;
    }

    string electionId = argv[1];

    // **BFV Scheme Parameter Setup**
    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetPlaintextModulus(65537);          // Small modulus for integers like 0 and 1
    parameters.SetMultiplicativeDepth(2);           // Depth for basic operations
    parameters.SetSecurityLevel(HEStd_128_classic); // 128-bit security
    parameters.SetRingDim(8192);                    // Ring dimension for performance

    // **Generate Crypto Context**
    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);
    if (!cryptoContext) {
        cerr << "Failed to generate CryptoContext" << endl;
        return 1;
    }
    cryptoContext->Enable(PKE);        // Enable public-key encryption
    cryptoContext->Enable(KEYSWITCH);  // Enable key switching
    cryptoContext->Enable(LEVELEDSHE); // Enable leveled SHE

    // **Generate Key Pair**
    KeyPair<DCRTPoly> keyPair = cryptoContext->KeyGen();
    if (!keyPair.good()) {
        cerr << "Key generation failed" << endl;
        return 1;
    }
    cout << "Key pair generated successfully." << endl;

    // **Create Directory for Outputs**
    string folderName = electionId + "_credentials";
    fs::create_directory(folderName);

    // **Serialize Crypto Context**
    string contextFile = folderName + "/cryptocontext.bin";
    if (!Serial::SerializeToFile(contextFile, cryptoContext, SerType::BINARY)) {
        cerr << "Error serializing crypto context to " << contextFile << endl;
        return 1;
    }

    // **Serialize Public Key**
    string publicKeyFile = folderName + "/public_key.bin";
    if (!Serial::SerializeToFile(publicKeyFile, keyPair.publicKey, SerType::BINARY)) {
        cerr << "Error serializing public key to " << publicKeyFile << endl;
        return 1;
    }

    // **Serialize Private Key**
    string privateKeyFile = folderName + "/private_key.bin";
    if (!Serial::SerializeToFile(privateKeyFile, keyPair.secretKey, SerType::BINARY)) {
        cerr << "Error serializing private key to " << privateKeyFile << endl;
        return 1;
    }
    cout << "Crypto context and keys serialized to " << folderName << endl;

    return 0;
}