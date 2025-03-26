#include <iostream>
#include <sstream>
#include <fstream>
#include <string>
#include <vector>
#include "openfhe.h"

using namespace std;
using namespace lbcrypto;

string base64Encode(const string &in) {
    static const string base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
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
    if (valb > -6) out.push_back(base64_chars[((val << 8) >> (valb + 8)) & 0x3F]);
    while (out.size() % 4) out.push_back('=');
    return out;
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        cout << "Usage: " << argv[0] << " \"<one-hot-vector>\" <election_id>" << endl;
        return 1;
    }

    string oneHotVectorStr = argv[1];
    string election_id = argv[2];
    string baseDir = "election_credentials/";
    string contextPath = baseDir + election_id + "_cryptocontext.cc";
    string publicKeyPath = baseDir + election_id + "_public_key.pk";

    cout << "Election ID: " << election_id << endl;
    cout << "Crypto Context File: " << contextPath << endl;
    cout << "Public Key File: " << publicKeyPath << endl;

    // Parse one-hot vector
    vector<int64_t> voteVector;
    stringstream ss(oneHotVectorStr);
    int64_t value;
    while (ss >> value) voteVector.push_back(value);
    if (voteVector.empty()) {
        cerr << "Error: Invalid one-hot vector input" << endl;
        return 1;
    }
    cout << "One-hot vector parsed successfully: ";
    for (auto v : voteVector) cout << v << " ";
    cout << endl;

    // Load crypto context
    CryptoContext<DCRTPoly> cryptoContext;
    if (!Serial::DeserializeFromFile(contextPath, cryptoContext, SerType::BINARY)) {
        cerr << "Error: Failed to deserialize crypto context from file " << contextPath << endl;
        return 1;
    }
    cout << "Crypto context loaded successfully!" << endl;

    // Load public key
    PublicKey<DCRTPoly> publicKey;
    if (!Serial::DeserializeFromFile(publicKeyPath, publicKey, SerType::BINARY)) {
        cerr << "Error: Failed to deserialize public key from file " << publicKeyPath << endl;
        return 1;
    }
    cout << "Public key deserialized successfully!" << endl;

    // Create plaintext
    Plaintext plaintext = cryptoContext->MakePackedPlaintext(voteVector);

    // Encrypt using the loaded context and public key
    auto ciphertext = cryptoContext->Encrypt(publicKey, plaintext);

    // Serialize and encode
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

    cout << "=== ENCRYPTED VOTE DATA ===" << endl;
    cout << encryptedVoteBase64 << endl;
    cout << "===========================" << endl;

    return 0;
}