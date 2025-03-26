#include <iostream>
#include <sstream>
#include <string>
#include <fstream>
#include <filesystem>  // C++17 filesystem library
#include "openfhe.h"

using namespace std;
using namespace lbcrypto;
namespace fs = std::filesystem;

// Simple Base64 encoding function.
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

int main(int argc, char* argv[]) {
    if(argc < 2) {
        cerr << "Usage: " << argv[0] << " <election_id>" << endl;
        return 1;
    }
    string election_id = argv[1];
    string baseDir = "election_credentials/";

    // Ensure the directory exists.
    if (!fs::exists(baseDir)) {
        if (!fs::create_directory(baseDir)) {
            cerr << "Error: Unable to create directory " << baseDir << endl;
            return 1;
        }
    }

    // Initialize OpenFHE context with BFV scheme parameters.
    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetPlaintextModulus(65537);
    parameters.SetMultiplicativeDepth(1);
    
    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);
    cryptoContext->Enable(PKE);
    cryptoContext->Enable(KEYSWITCH);
    cryptoContext->Enable(LEVELEDSHE);
    
    // Generate the key pair using the generated context.
    KeyPair<DCRTPoly> keyPair = cryptoContext->KeyGen();
    if (!keyPair.good()) {
        cerr << "Key generation failed" << endl;
        return 1;
    }
    cout << "Keys generated successfully." << endl;
    
    // Save the crypto context and keys at the end.
    try {
        string contextPath = baseDir + election_id + "_cryptocontext.cc";
        cout << "Serializing crypto context to file (" << contextPath << ")..." << endl;
        if (!Serial::SerializeToFile(contextPath, cryptoContext, SerType::BINARY)) {
            cerr << "Error: Failed to serialize crypto context to file." << endl;
            return 1;
        }
        cout << "Crypto context successfully saved to " << contextPath << endl;
        
        string publicKeyPath = baseDir + election_id + "_public_key.pk";
        if (!Serial::SerializeToFile(publicKeyPath, keyPair.publicKey, SerType::BINARY)) {
            cerr << "Error: Failed to serialize public key to file." << endl;
            return 1;
        }
        cout << "Public key saved to " << publicKeyPath << endl;
        
        string privateKeyPath = baseDir + election_id + "_private_key.sk";
        if (!Serial::SerializeToFile(privateKeyPath, keyPair.secretKey, SerType::BINARY)) {
            cerr << "Error: Failed to serialize private key to file." << endl;
            return 1;
        }
        cout << "Private key saved to " << privateKeyPath << endl;
    } catch (const exception& e) {
        cerr << "Exception during serialization: " << e.what() << endl;
        return 1;
    }
    
    // Additionally, serialize keys to Base64 strings and print them (optional).
    // stringstream publicStream;
    // Serial::Serialize(keyPair.publicKey, publicStream, SerType::BINARY);
    // string publicStr = publicStream.str();
    // string publicKeyBase64 = base64Encode(publicStr);
    
    // stringstream privateStream;
    // Serial::Serialize(keyPair.secretKey, privateStream, SerType::BINARY);
    // string privateStr = privateStream.str();
    // string privateKeyBase64 = base64Encode(privateStr);
    
    // cout << "Public Key (Base64):" << endl;
    // cout << publicKeyBase64 << endl << endl;
    
    // cout << "Private Key (Base64):" << endl;
    // cout << privateKeyBase64 << endl;
    
    
    return 0;
}
