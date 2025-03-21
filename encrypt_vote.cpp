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

// Base64 character set.
static const string base64_chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";

// Base64 encoding function.
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

// Base64 decoding function.
string base64Decode(const string &in) {
    string out;
    vector<int> T(256, -1);
    for (int i = 0; i < 64; i++){
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

int main(int argc, char* argv[]){
    if(argc < 2){
        cout << "Usage: " << argv[0] << " \"<one-hot-vector>\"" << endl;
        return 1;
    }
    
    // Step 1: Parse the one-hot vector.
    string oneHotVectorStr = argv[1];  // Space-separated one-hot encoded vector.
    cout << "Received One-Hot Vector: " << oneHotVectorStr << endl;
    vector<int64_t> voteVector;
    stringstream ss(oneHotVectorStr);
    int64_t value;
    while(ss >> value){
        voteVector.push_back(value);
    }
    if(voteVector.empty()){
        cerr << "Error: Invalid one-hot vector input" << endl;
        return 1;
    }
    cout << "One-hot vector parsed successfully: ";
    for(auto v : voteVector)
        cout << v << " ";
    cout << endl;
    
    // Step 2: Load the crypto context and public key from the combined file.
    ifstream inFile("context_and_pubkey.txt", ios::binary);
    if(!inFile.is_open()){
        cerr << "Error: Could not open context_and_pubkey.txt" << endl;
        return 1;
    }
    CryptoContext<DCRTPoly> cryptoContext;
    try {
        Serial::Deserialize(cryptoContext, inFile, SerType::BINARY);
    } catch (const exception &e) {
        cerr << "Error deserializing crypto context: " << e.what() << endl;
        return 1;
    }
    PublicKey<DCRTPoly> publicKey;
    try {
        Serial::Deserialize(publicKey, inFile, SerType::BINARY);
    } catch (const exception &e) {
        cerr << "Error deserializing public key: " << e.what() << endl;
        return 1;
    }
    inFile.close();
    cout << "Crypto context and public key loaded successfully from context_and_pubkey.txt" << endl;
    
    // Step 3: Create plaintext from the one-hot vector using the loaded crypto context.
    Plaintext plaintext = cryptoContext->MakePackedPlaintext(voteVector);
    
    // Step 4: Encrypt the plaintext vote using the public key.
    auto ciphertext = cryptoContext->Encrypt(publicKey, plaintext);
    
    // Step 5: Serialize the ciphertext to binary and then Base64 encode it.
    stringstream os;
    Serial::Serialize(ciphertext, os, SerType::BINARY);
    string cipherStr = os.str();
    if(cipherStr.empty()){
        cerr << "Error: Failed to serialize ciphertext" << endl;
        return 1;
    }
    string encryptedVoteBase64 = base64Encode(cipherStr);
    if(encryptedVoteBase64.empty()){
        cerr << "Error: Base64 encryption result is empty" << endl;
        return 1;
    }
    
    // Step 6: Output the encrypted vote.
    cout << "=== ENCRYPTED VOTE DATA ===" << endl;
    cout << encryptedVoteBase64 << endl;
    cout << "===========================" << endl;
    
    return 0;
}
