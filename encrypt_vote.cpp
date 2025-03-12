#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <iomanip>
#include <stdexcept>
#include <functional>
#include "openfhe.h"

using namespace std;
using namespace lbcrypto;

// Base64 encoding function.
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

// Simple Base64 decoding function.
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
        cout << "Usage: " << argv[0] << " <candidate_id> <public_key_base64>" << endl;
        return 1;
    }
    
    string candidateId = argv[1];
    string publicKeyBase64 = argv[2];
    
    // Initialize OpenFHE context with the same parameters as used in keygen.
    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetPlaintextModulus(65537);
    parameters.SetMultiplicativeDepth(1);
    
    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);
    cryptoContext->Enable(PKE);
    cryptoContext->Enable(KEYSWITCH);
    cryptoContext->Enable(LEVELEDSHE);
    
    // Deserialize the provided public key.
    string publicKeyBinary = base64Decode(publicKeyBase64);
    stringstream publicStream(publicKeyBinary);
    PublicKey<DCRTPoly> publicKey;
    Serial::Deserialize(publicKey, publicStream, SerType::BINARY);
    
    // Convert candidateId to a vote value.
    int64_t voteValue;
    try {
        // If candidateId is long (e.g., a UUID), hash it.
        if (candidateId.size() > 10) {
            hash<string> hasher;
            voteValue = static_cast<int64_t>(hasher(candidateId) % 1000);
        } else {
            voteValue = stoll(candidateId);
        }
    } catch (...) {
        voteValue = 1;
    }
    
    vector<int64_t> voteVector = { voteValue };
    Plaintext plaintext = cryptoContext->MakePackedPlaintext(voteVector);
    
    // Encrypt the plaintext vote using the deserialized public key.
    auto ciphertext = cryptoContext->Encrypt(publicKey, plaintext);
    
    // Serialize the ciphertext to binary and then Base64 encode.
    stringstream os;
    Serial::Serialize(ciphertext, os, SerType::BINARY);
    string serializedData = os.str();
    string encryptedVoteBase64 = base64Encode(serializedData);
    
    cout << "=== ENCRYPTED VOTE DATA ===" << endl;
    cout << encryptedVoteBase64 << endl;
    cout << "===========================" << endl;
    
    return 0;
}
