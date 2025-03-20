#include <iostream>
#include <sstream>
#include <fstream>
#include <string>
#include <vector>
#include <iomanip>
#include <stdexcept>
#include <functional>
#include <algorithm>
#include "openfhe.h"

using namespace std;
using namespace lbcrypto;

// Base64 encoding function
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

// Base64 decoding function
string base64Decode(const string &in) {
    string out;
    vector<int> T(256, -1);
    for (int i = 0; i < 64; i++) {
        T[base64_chars[i]] = i;
    }
    int val = 0, valb = -8;
    for (unsigned char c : in) {
        if (T[c] == -1) break;
        val = (val << 6) + T[c];
        valb += 6;
        if (valb >= 0) {
            out.push_back(char((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return out;
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        cout << "Usage: " << argv[0] << " \"<one-hot-vector>\" <public_key_file_path>" << endl;
        return 1;
    }

    string oneHotVectorStr = argv[1]; // Space-separated one-hot encoded vector
    string publicKeyFilePath = argv[2];

    cout << "Received One-Hot Vector: " << oneHotVectorStr << endl;
    cout << "Public Key File Path: " << publicKeyFilePath << endl;

    // ✅ Step 1: Parse the one-hot vector
    vector<int64_t> voteVector;
    stringstream ss(oneHotVectorStr);
    int64_t value;
    while (ss >> value) {
        voteVector.push_back(value);
    }

    if (voteVector.empty()) {
        cerr << "Error: Invalid one-hot vector input" << endl;
        return 1;
    }

    cout << "✅ One-hot vector parsed successfully: ";
    for (int v : voteVector) cout << v << " ";
    cout << endl;

    // ✅ Step 2: Read the public key from file
    ifstream keyFile(publicKeyFilePath);
    if (!keyFile.is_open()) {
        cerr << "Error: Cannot open file: " << publicKeyFilePath << endl;
        return 1;
    }
    
    string line;
    string publicKeyBase64;
    string prefix = "openfhe_public_key:";
    while (getline(keyFile, line)) {
        if (line.substr(0, prefix.size()) == prefix) {
            publicKeyBase64 = line.substr(prefix.size());
            // Trim whitespace from the extracted key.
            publicKeyBase64.erase(publicKeyBase64.begin(), 
                find_if(publicKeyBase64.begin(), publicKeyBase64.end(), [](unsigned char ch) {
                    return !isspace(ch);
                })
            );
            publicKeyBase64.erase(
                find_if(publicKeyBase64.rbegin(), publicKeyBase64.rend(), [](unsigned char ch) {
                    return !isspace(ch);
                }).base(), publicKeyBase64.end()
            );
            break;
        }
    }
    keyFile.close();
    
    if (publicKeyBase64.empty()) {
        cerr << "Error: Public key not found in file" << endl;
        return 1;
    }

    // ✅ Debug: Print extracted key
    cout << "✅ Extracted Public Key (Base64): " << publicKeyBase64 << endl;

    // ✅ Check if the key is empty
    if (publicKeyBase64.empty()) {
        cerr << "❌ ERROR: Public key not found in file " << publicKeyFilePath << endl;
        return 1;
    }

    // ✅ Decode Base64
    string publicKeyBinary = base64Decode(publicKeyBase64);
    if (publicKeyBinary.empty()) {
        cerr << "❌ ERROR: Base64-decoded public key is empty" << endl;
        return 1;
    }

        // ✅ Deserialize Public Key
    stringstream publicStream(publicKeyBinary);
    PublicKey<DCRTPoly> publicKey;
    Serial::Deserialize(publicKey, publicStream, SerType::BINARY);

    if (!publicKey) {
        cerr << "❌ ERROR: Failed to deserialize public key" << endl;
        return 1;
    }

    cout << "✅ Public key deserialized successfully!" << endl;

    // ✅ Step 3: Initialize OpenFHE context
    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetPlaintextModulus(65537);
    parameters.SetMultiplicativeDepth(1);
        
    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);
    cryptoContext->Enable(PKE);
    cryptoContext->Enable(KEYSWITCH);
    cryptoContext->Enable(LEVELEDSHE);

    if (!cryptoContext) {
        cerr << "❌ ERROR: Failed to initialize OpenFHE CryptoContext" << endl;
        return 1;
    }

    // ✅ Step 5: Create plaintext from the one-hot vector
    Plaintext plaintext = cryptoContext->MakePackedPlaintext(voteVector);

    // ✅ Step 6: Encrypt the plaintext vote using the public key
    auto ciphertext = cryptoContext->Encrypt(publicKey, plaintext);

    // ✅ Step 7: Serialize the ciphertext to binary and then Base64 encode
    stringstream os;
    Serial::Serialize(ciphertext, os, SerType::BINARY);

    if (os.str().empty()) {
        cerr << "Error: Failed to serialize ciphertext" << endl;
        return 1;
    }

    string encryptedVoteBase64 = base64Encode(os.str());
    if (encryptedVoteBase64.empty()) {
        cerr << "Error: Base64 encryption result is empty" << endl;
        return 1;
    }

    // ✅ Step 8: Output the encrypted vote
    cout << "=== ENCRYPTED VOTE DATA ===" << endl;
    cout << encryptedVoteBase64 << endl;
    cout << "===========================" << endl;

    return 0;
}
