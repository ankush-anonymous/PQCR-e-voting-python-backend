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

    // Step 1: Parse the one-hot vector.
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
    cout << "One-hot vector parsed successfully: ";
    for (int v : voteVector) cout << v << " ";
    cout << endl;

    // Step 2: Read the public key from file.
    ifstream keyFile(publicKeyFilePath, ios::binary);
    if (!keyFile.is_open()) {
        cerr << "Error: Cannot open file: " << publicKeyFilePath << endl;
        return 1;
    }
    string publicKeyBinary((istreambuf_iterator<char>(keyFile)), istreambuf_iterator<char>());
    keyFile.close();

    if (publicKeyBinary.empty()) {
        cerr << "Error: Public key file is empty" << endl;
        return 1;
    }

    // Deserialize Public Key from the binary data.
    stringstream publicStream(publicKeyBinary);
    PublicKey<DCRTPoly> publicKey;
    Serial::Deserialize(publicKey, publicStream, SerType::BINARY);
    if (!publicKey) {
        cerr << "ERROR: Failed to deserialize public key" << endl;
        return 1;
    }
    cout << "Public key deserialized successfully!" << endl;

    // Step 3: Initialize OpenFHE context by loading it from file.
    CryptoContext<DCRTPoly> cryptoContext;
    if (!Serial::DeserializeFromFile("cryptocontext.txt", cryptoContext, SerType::BINARY)) {
        cerr << "Error: Could not load crypto context." << endl;
        return 1;
    }
    cryptoContext->Enable(PKE);
    cryptoContext->Enable(KEYSWITCH);
    cryptoContext->Enable(LEVELEDSHE);
    if (!cryptoContext) {
        cerr << "ERROR: Failed to initialize OpenFHE CryptoContext" << endl;
        return 1;
    }

    // Debug: Check if the public key is compatible with the current context
    if (!cryptoContext->GetCryptoParameters()->GetElementParams()->GetParams().at(0)->Equals(publicKey->GetCryptoParameters()->GetElementParams()->GetParams().at(0))) {
        cerr << "ERROR: Public key parameters do not match the context." << endl;
        return 1;
    }

    // Step 4: Create plaintext from the one-hot vector.
    Plaintext plaintext = cryptoContext->MakePackedPlaintext(voteVector);

    // Step 5: Encrypt the plaintext vote using the public key.
    auto ciphertext = cryptoContext->Encrypt(publicKey, plaintext);

    // Step 6: Serialize the ciphertext to binary and then Base64 encode.
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

    // Step 7: Output the encrypted vote.
    cout << "=== ENCRYPTED VOTE DATA ===" << endl;
    cout << encryptedVoteBase64 << endl;
    cout << "===========================" << endl;

    return 0;
}
