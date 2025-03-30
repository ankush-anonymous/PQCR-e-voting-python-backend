#include <openfhe.h>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <vector>
#include <string>
#include <sstream>
#include <algorithm>

#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/bfvrns/bfvrns-ser.h"

using namespace lbcrypto;
using namespace std;
namespace fs = std::filesystem;

// Helper: trim whitespace from both ends.
string trim(const string &s) {
    auto start = s.begin();
    while (start != s.end() && isspace(*start)) { start++; }
    auto end = s.end();
    do { end--; } while (distance(start, end) > 0 && isspace(*end));
    return string(start, end + 1);
}

// Parse a one-hot vector from a string. Accepts "[0,1,1]" or "0,1,1".
vector<int64_t> parseVector(const string& vectorStr) {
    string s = vectorStr;
    // Remove surrounding brackets if present.
    if (!s.empty() && s.front() == '[' && s.back() == ']') {
        s = s.substr(1, s.size() - 2);
    }
    vector<int64_t> result;
    stringstream ss(s);
    string token;
    while (getline(ss, token, ',')) {
        token = trim(token);
        if (!token.empty()) {
            try {
                result.push_back(stoll(token));
            } catch (const std::exception& e) {
                throw runtime_error("Invalid vector element: " + token);
            }
        }
    }
    return result;
}

void encryptVector(const string& electionId, const string& voterId, const vector<int64_t>& oneHotVector) {
    try {
        // Construct file paths based on the election ID.
        string folder = electionId + "_credentials/";
        string contextFile = folder + "cryptocontext.bin";
        string publicKeyFile = folder + "public_key.bin";

        // Check that the necessary files exist.
        if (!fs::exists(contextFile)) {
            throw runtime_error("Context file not found: " + contextFile);
        }
        if (!fs::exists(publicKeyFile)) {
            throw runtime_error("Public key file not found: " + publicKeyFile);
        }

        // Deserialize crypto context.
        CryptoContext<DCRTPoly> cc;
        if (!Serial::DeserializeFromFile(contextFile, cc, SerType::BINARY)) {
            throw runtime_error("Failed to deserialize crypto context from " + contextFile);
        }
        cc->Enable(PKE);
        cc->Enable(KEYSWITCH);
        cc->Enable(LEVELEDSHE);

        // Deserialize public key.
        PublicKey<DCRTPoly> publicKey;
        if (!Serial::DeserializeFromFile(publicKeyFile, publicKey, SerType::BINARY)) {
            throw runtime_error("Failed to deserialize public key from " + publicKeyFile);
        }

        // Encrypt the one-hot vector.
        Plaintext plaintext = cc->MakeCoefPackedPlaintext(oneHotVector);
        Ciphertext<DCRTPoly> ciphertext = cc->Encrypt(publicKey, plaintext);
        if (!ciphertext) {
            throw runtime_error("Failed to encrypt the vector");
        }

        // Ensure the output folder exists.
        string outputFolder = "encrypted_votes/";
        if (!fs::exists(outputFolder)) {
            fs::create_directory(outputFolder);
        }
        // Construct output file path using voter_id.
        string outputFilePath = outputFolder + voterId + "_encrypted_vote.bin";

        // Serialize and save the ciphertext.
        if (!Serial::SerializeToFile(outputFilePath, ciphertext, SerType::BINARY)) {
            throw runtime_error("Failed to serialize ciphertext to " + outputFilePath);
        }
        cout << "=== ENCRYPTED VOTE DATA ===" << endl;
        cout << "Vector encrypted and saved to " << outputFilePath << endl;
    } catch (const exception& e) {
        cerr << "Error: " << e.what() << endl;
        throw;
    }
}

int main(int argc, char* argv[]) {
    // Expected usage:
    //   ./encrypt_vote <election_id> <voter_id> <one_hot_vector>
    // Example:
    //   ./encrypt_vote "mumbai-election-cb08603e" "voter123" "[0,1,1]"
    if (argc != 4) {
        cerr << "Usage: " << argv[0] << " <election_id> <voter_id> <one_hot_vector>" << endl;
        cerr << "Example: " << argv[0] << " \"mumbai-election-cb08603e\" \"voter123\" \"[0,1,1]\"" << endl;
        return 1;
    }

    string electionId = argv[1];
    string voterId = argv[2];
    string vectorStr = argv[3];

    vector<int64_t> oneHotVector;
    try {
        oneHotVector = parseVector(vectorStr);
    } catch (const exception& e) {
        cerr << "Error parsing vector: " << e.what() << endl;
        return 1;
    }

    cout << "Election ID: " << electionId << endl;
    cout << "Voter ID: " << voterId << endl;
    cout << "One-hot vector parsed successfully: ";
    for (auto v : oneHotVector) {
        cout << v << " ";
    }
    cout << endl;

    try {
        encryptVector(electionId, voterId, oneHotVector);
    } catch (const exception& e) {
        return 1;
    }
    return 0;
}
