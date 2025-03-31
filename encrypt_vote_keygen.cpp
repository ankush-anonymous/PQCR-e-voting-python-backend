#include <openfhe.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <filesystem>

#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/bfvrns/bfvrns-ser.h"

using namespace lbcrypto;
using namespace std;
namespace fs = std::filesystem;

// Base64 characters and encoding function.
static const string base64_chars = 
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";

string base64Encode(const string &in) {
    string out;
    int val = 0, valb = -6;
    for (unsigned char c : in) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            out.push_back(base64_chars[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6) {
        out.push_back(base64_chars[((val << 8) >> (valb + 8)) & 0x3F]);
    }
    while (out.size() % 4) {
        out.push_back('=');
    }
    return out;
}

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
    parameters.SetPlaintextModulus(65537);
    parameters.SetMultiplicativeDepth(2);
    parameters.SetSecurityLevel(HEStd_128_classic);
    parameters.SetRingDim(8192);

    // **Generate Crypto Context**
    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);
    if (!cryptoContext) {
        cerr << "Failed to generate CryptoContext" << endl;
        return 1;
    }
    cryptoContext->Enable(PKE);
    cryptoContext->Enable(KEYSWITCH);
    cryptoContext->Enable(LEVELEDSHE);

    

    // **Generate Key Pair**
    KeyPair<DCRTPoly> keyPair = cryptoContext->KeyGen();
    if (!keyPair.good()) {
        cerr << "Key generation failed" << endl;
        return 1;
    }

    // **Create Directory for Outputs**
    string folderName = electionId + "_credentials";
    fs::create_directory(folderName);

    // **Serialize Crypto Context and Keys to Disk**
    string contextFile = folderName + "/cryptocontext.bin";
    if (!Serial::SerializeToFile(contextFile, cryptoContext, SerType::BINARY)) {
        cerr << "Error serializing crypto context to " << contextFile << endl;
        return 1;
    }
    string publicKeyFile = folderName + "/public_key.bin";
    if (!Serial::SerializeToFile(publicKeyFile, keyPair.publicKey, SerType::BINARY)) {
        cerr << "Error serializing public key to " << publicKeyFile << endl;
        return 1;
    }
    string privateKeyFile = folderName + "/private_key.bin";
    if (!Serial::SerializeToFile(privateKeyFile, keyPair.secretKey, SerType::BINARY)) {
        cerr << "Error serializing private key to " << privateKeyFile << endl;
        return 1;
    }
    cout << "Serialized CryptoContext and keys saved to " << folderName << endl;

    // **Serialize Keys to Strings and Base64-Encode Them**
    string publicKey, privateKey;
    {
        stringstream publicStream;
        Serial::Serialize(keyPair.publicKey, publicStream, SerType::BINARY);
        publicKey = base64Encode(publicStream.str());
    }
    {
        stringstream privateStream;
        Serial::Serialize(keyPair.secretKey, privateStream, SerType::BINARY);
        privateKey = base64Encode(privateStream.str());
    }

    // **Return Keys to Stdout**
    cout << "Public Key (Base64):" << endl;
    cout << publicKey << endl << endl;
    cout << "Private Key (Base64):" << endl;
    cout << privateKey << endl;

    return 0;
}
