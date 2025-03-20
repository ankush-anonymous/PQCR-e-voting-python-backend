#include <iostream>
#include <sstream>
#include <string>
#include <iomanip>
#include <functional>
#include <fstream>
#include "openfhe.h"

using namespace std;
using namespace lbcrypto;

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

int main() {
    // Initialize OpenFHE context with BFV scheme parameters.
    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetPlaintextModulus(65537);
    parameters.SetMultiplicativeDepth(1);
    
    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);
    cryptoContext->Enable(PKE);
    cryptoContext->Enable(KEYSWITCH);
    cryptoContext->Enable(LEVELEDSHE);
    
    // // ... after initializing your cryptoContext
    // ofstream contextFile("cryptocontext.txt", ios::binary);
    // if (!contextFile.is_open()) {
    //     cerr << "Error: Could not open file to write crypto context." << endl;
    //     return 1;
    // }
    // Serial::Serialize(cryptoContext, contextFile, SerType::BINARY);
    // contextFile.close();

        // Save the crypto context to file
    cout << "Serializing crypto context to file..." << endl;
    if (!Serial::SerializeToFile("cryptocontext.txt", cryptoContext, SerType::BINARY)) {
        cerr << "Error: Failed to serialize crypto context to file." << endl;
        return 1;
    }
    cout << "Crypto context successfully saved to cryptocontext.txt" << endl;

    // Generate key pair.
    KeyPair<DCRTPoly> keyPair = cryptoContext->KeyGen();
    if (!keyPair.good()) {
        cerr << "Key generation failed" << endl;
        return 1;
    }
    cout << "Keys generated successfully." << endl;
    
    // Serialize public key.
    stringstream publicStream;
    Serial::Serialize(keyPair.publicKey, publicStream, SerType::BINARY);
    string publicStr = publicStream.str();
    string publicKeyBase64 = base64Encode(publicStr);
    
    // Serialize private key.
    stringstream privateStream;
    Serial::Serialize(keyPair.secretKey, privateStream, SerType::BINARY);
    string privateStr = privateStream.str();
    string privateKeyBase64 = base64Encode(privateStr);
    
    cout << "Public Key (Base64):" << endl;
    cout << publicKeyBase64 << endl << endl;
    
    cout << "Private Key (Base64):" << endl;
    cout << privateKeyBase64 << endl;
    
    return 0;
}
