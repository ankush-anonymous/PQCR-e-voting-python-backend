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
    
    // Generate key pair.
    KeyPair<DCRTPoly> keyPair = cryptoContext->KeyGen();
    if (!keyPair.good()) {
        cerr << "Key generation failed" << endl;
        return 1;
    }
    cout << "Keys generated successfully." << endl;
    
    // Open a file to write both the crypto context and the public key.
    ofstream outFile("context_and_pubkey.txt", ios::binary);
    if (!outFile.is_open()) {
        cerr << "Error: Could not open file to write context and public key." << endl;
        return 1;
    }
    
    try {
        // Serialize the crypto context first.
        Serial::Serialize(cryptoContext, outFile, SerType::BINARY);
        // Then serialize the public key.
        Serial::Serialize(keyPair.publicKey, outFile, SerType::BINARY);
    } catch (const exception &e) {
        cerr << "Error during serialization: " << e.what() << endl;
        return 1;
    }
    outFile.close();
    cout << "Crypto context and public key successfully saved to context_and_pubkey.txt" << endl;
    
    // Optional verification: deserialize them back from the same file.
    ifstream inFile("context_and_pubkey.txt", ios::binary);
    if (!inFile.is_open()) {
        cerr << "Error: Could not open context_and_pubkey.txt for reading." << endl;
        return 1;
    }
    CryptoContext<DCRTPoly> loadedContext;
    try {
        Serial::Deserialize(loadedContext, inFile, SerType::BINARY);
    } catch (const exception &e) {
        cerr << "Error: Failed to deserialize crypto context from context_and_pubkey.txt: " << e.what() << endl;
        return 1;
    }
    // Deserialize the public key from the same stream.
    PublicKey<DCRTPoly> loadedPublicKey;
    try {
        Serial::Deserialize(loadedPublicKey, inFile, SerType::BINARY);
    } catch (const exception &e) {
        cerr << "Error: Failed to deserialize public key from context_and_pubkey.txt: " << e.what() << endl;
        return 1;
    }
    inFile.close();
    cout << "Successfully verified the serialized context and public key can be loaded back." << endl;
    
    // Serialize public key separately for output (Base64-encoded).
    stringstream publicStream;
    Serial::Serialize(keyPair.publicKey, publicStream, SerType::BINARY);
    string publicStr = publicStream.str();
    string publicKeyBase64 = base64Encode(publicStr);
    
    // Serialize private key separately.
    stringstream privateStream;
    Serial::Serialize(keyPair.secretKey, privateStream, SerType::BINARY);
    string privateStr = privateStream.str();
    string privateKeyBase64 = base64Encode(privateStr);
    
    // Return (print) the public and private keys.
    cout << "Public Key (Base64):" << endl;
    cout << publicKeyBase64 << endl << endl;
    
    cout << "Private Key (Base64):" << endl;
    cout << privateKeyBase64 << endl;
    
    return 0;
}
