#include <iostream>
#include <sstream>
#include <fstream>
#include <string>
#include <vector>
#include "openfhe.h"
#include "cryptocontext-ser.h" // For unified serialization
#include "key/key-ser.h"       // For key serialization

using namespace std;
using namespace lbcrypto;

// Base64 encoding function.
string base64Encode(const string &in) {
    static const string base64_chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
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
    if (valb > -6)
        out.push_back(base64_chars[((val << 8) >> (valb + 8)) & 0x3F]);
    while (out.size() % 4)
        out.push_back('=');
    return out;
}

// Define the unified key material structure at global scope.
struct KeyMaterial {
    CryptoContext<DCRTPoly> cryptoContext;
    PublicKey<DCRTPoly> publicKey;
    PrivateKey<DCRTPoly> secretKey; // For completeness

    template <class Archive>
    void serialize(Archive & ar) {
        ar(cryptoContext, publicKey, secretKey);
    }
};

int main(int argc, char* argv[]) {
    if (argc < 3) {
        cout << "Usage: " << argv[0] << " \"<one-hot-vector>\" <election_id>" << endl;
        return 1;
    }

    // Read command line arguments.
    string oneHotVectorStr = argv[1];
    string election_id = argv[2];
    string baseDir = "election_credentials/";
    // Use the unified key material file generated during key generation.
    string keyMaterialPath = baseDir + election_id + "_keymaterial.bin";

    cout << "Election ID: " << election_id << endl;
    cout << "Key Material File: " << keyMaterialPath << endl;

    // Step 1: Parse the one-hot vector.
    vector<int64_t> voteVector;
    stringstream ss(oneHotVectorStr);
    int64_t value;
    while (ss >> value)
        voteVector.push_back(value);
    if (voteVector.empty()) {
        cerr << "Error: Invalid one-hot vector input" << endl;
        return 1;
    }
    cout << "One-hot vector parsed successfully: ";
    for (auto v : voteVector)
        cout << v << " ";
    cout << endl;

    // Step 2: Load the unified key material from file.
    KeyMaterial km;
    if (!Serial::DeserializeFromFile(keyMaterialPath, km, SerType::BINARY)) {
        cerr << "Error: Failed to deserialize key material from file " << keyMaterialPath << endl;
        return 1;
    }
    cout << "Key material loaded successfully!" << endl;

    // Get the crypto parameters from the context and the key
    auto ctxParams = km.cryptoContext->GetCryptoParameters();
    auto keyParams = km.publicKey->GetCryptoParameters();

    // Print out some key parameters.
    cout << "Context plaintext modulus: " << ctxParams->GetPlaintextModulus() << endl;
    cout << "Key plaintext modulus:     " << keyParams->GetPlaintextModulus() << endl;

    // If available, print out element (ring) parameters.
    auto ctxElemParams = ctxParams->GetElementParams();
    auto keyElemParams = keyParams->GetElementParams();

    if (ctxElemParams && keyElemParams) {
        // You may print properties like modulus and degree if such functions are provided.
        cout << "Context poly modulus: " << ctxElemParams->GetModulus() << endl;
        cout << "Key poly modulus:     " << keyElemParams->GetModulus() << endl;
        cout << "Context ring degree:  " << ctxElemParams->GetCyclotomicOrder() << endl;
        cout << "Key ring degree:      " << keyElemParams->GetCyclotomicOrder() << endl;
    }

    // (Optional) Re-enable features if needed.
    km.cryptoContext->Enable(PKE);
    km.cryptoContext->Enable(KEYSWITCH);
    km.cryptoContext->Enable(LEVELEDSHE);

    // Step 3: Create plaintext from the one-hot vector.
    Plaintext plaintext = km.cryptoContext->MakePackedPlaintext(voteVector);

    // Step 4: Encrypt using the loaded context and public key.
    auto ciphertext = km.cryptoContext->Encrypt(km.publicKey, plaintext);
    if (!ciphertext) {
        cerr << "Error: Encryption failed." << endl;
        return 1;
    }

    // Step 5: Serialize and Base64-encode the ciphertext.
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
