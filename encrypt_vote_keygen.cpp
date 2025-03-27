#include <openfhe.h>
#include <iostream>
#include <sstream>
#include <fstream>
#include <string>
#include <filesystem>  // C++17 filesystem library

#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/ckksrns/ckksrns-ser.h"

using namespace lbcrypto;
using namespace std;
namespace fs = std::filesystem;

int main(int argc, char *argv[]) {

    // Check for the election ID argument.
    if (argc < 2) {
        cerr << "Usage: " << argv[0] << " <election_id>" << endl;
        return 1;
    }
    // Use the provided election ID for file naming.
    string election_id = argv[1];

    // Set up BFV scheme parameters.
    uint64_t mod = 65537;
    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetPlaintextModulus(mod);
    parameters.SetMultiplicativeDepth(2);

    // Generate the crypto context using the specified parameters.
    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);
    cryptoContext->Enable(PKE);
    cryptoContext->Enable(KEYSWITCH);
    cryptoContext->Enable(LEVELEDSHE);

    // Generate a public/private key pair.
    KeyPair<DCRTPoly> keyPair = cryptoContext->KeyGen();
    if (!keyPair.good()) {
        cerr << "Key generation failed" << endl;
        return 1;
    }
    cout << "The key pair has been generated." << endl;

    // For diagnostic purposes, serialize the crypto context to a string and print its first 2000 characters.
    auto contextStr = Serial::SerializeToString(cryptoContext);
    cout << "Crypto Context (First 2000 characters):\n" << contextStr.substr(0, 2000) << endl;

    // Construct file names using the election ID.
    string binFile = election_id + "_cryptocontext.bin";
    string jsonFile = election_id + "_cryptocontext.txt";

    // Serialize the crypto context to a binary file.
    if (!Serial::SerializeToFile(binFile, cryptoContext, SerType::BINARY)) {
        cerr << "Error serializing crypto context to binary file." << endl;
        return 1;
    }
    // Serialize the crypto context to a JSON file.
    if (!Serial::SerializeToFile(jsonFile, cryptoContext, SerType::JSON)) {
        cerr << "Error serializing crypto context to JSON file." << endl;
        return 1;
    }
    cout << "Crypto context successfully serialized to files:" << endl;
    cout << "Binary: " << binFile << endl;
    cout << "JSON:   " << jsonFile << endl;

    return 0;
}
