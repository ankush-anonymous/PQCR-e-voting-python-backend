#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include <functional>
#include <algorithm>
#include <stdexcept>
#include "nlohmann/json.hpp"
#include "openfhe.h"

using namespace std;
using namespace lbcrypto;
using json = nlohmann::json;

// Base64 decoding function (as provided)
static const string base64_chars = 
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";

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

// Compute the vote value from the candidate ID, using the same logic as your encryptor.
int64_t computeVoteValue(const string &candidateId) {
    try {
        if (candidateId.size() > 10) {
            hash<string> hasher;
            return static_cast<int64_t>(hasher(candidateId) % 1000);
        } else {
            return stoll(candidateId);
        }
    } catch (...) {
        return 1;
    }
}

int main() {
    // Read the JSON file containing votes.
    ifstream inFile("encrypted_votes.json");
    if (!inFile.is_open()) {
        cerr << "Error: Cannot open encrypted_votes.json" << endl;
        return 1;
    }
    json votesData;
    inFile >> votesData;
    inFile.close();

    // Initialize the OpenFHE crypto context using the same parameters as keygen/encryption.
    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetPlaintextModulus(65537);
    parameters.SetMultiplicativeDepth(1);
    
    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);
    cryptoContext->Enable(PKE);
    cryptoContext->Enable(KEYSWITCH);
    cryptoContext->Enable(LEVELEDSHE);

    // Map to store the aggregated ciphertexts (one per candidate).
    map<string, Ciphertext<DCRTPoly>> aggregatedVotes;

    // Process each vote in the JSON.
    for (const auto &vote : votesData["votes"]) {
        string candidate = vote["candidate"];
        string encryptedVoteBase64 = vote["encrypted_vote"];

        // Base64 decode the ciphertext.
        string decoded = base64Decode(encryptedVoteBase64);
        stringstream ss(decoded);

        // Deserialize the ciphertext.
        Ciphertext<DCRTPoly> ct;
        Serial::Deserialize(ct, ss, SerType::BINARY);

        // Homomorphically aggregate votes for the same candidate.
        if (aggregatedVotes.find(candidate) != aggregatedVotes.end()) {
            aggregatedVotes[candidate] = cryptoContext->EvalAdd(aggregatedVotes[candidate], ct);
        } else {
            aggregatedVotes[candidate] = ct;
        }
    }

    // Read the private key from a text file (assumed to contain only the Base64-encoded key).
    ifstream pkFile("private_key.txt");
    if (!pkFile.is_open()) {
        cerr << "Error: Cannot open private_key.txt" << endl;
        return 1;
    }
    string privateKeyBase64;
    getline(pkFile, privateKeyBase64);
    pkFile.close();

    // Remove any leading/trailing whitespace.
    privateKeyBase64.erase(privateKeyBase64.begin(), 
        find_if(privateKeyBase64.begin(), privateKeyBase64.end(), [](unsigned char ch) {
            return !isspace(ch);
        })
    );
    privateKeyBase64.erase(
        find_if(privateKeyBase64.rbegin(), privateKeyBase64.rend(), [](unsigned char ch) {
            return !isspace(ch);
        }).base(), privateKeyBase64.end()
    );

    // Decode and deserialize the private key.
    string decodedPK = base64Decode(privateKeyBase64);
    stringstream pkStream(decodedPK);
    PrivateKey<DCRTPoly> secretKey;
    Serial::Deserialize(secretKey, pkStream, SerType::BINARY);

    // Decrypt each candidate’s aggregated vote and compute the vote count.
    cout << "Vote tally results:" << endl;
    for (const auto &entry : aggregatedVotes) {
        const string &candidate = entry.first;
        Ciphertext<DCRTPoly> aggregatedCt = entry.second;

        Plaintext plaintext;
        cryptoContext->Decrypt(secretKey, aggregatedCt, &plaintext);

        // Retrieve the packed plaintext vector.
        std::vector<int64_t> values = plaintext->GetPackedValue();
        int64_t aggregatedValue = values[0];

        int64_t voteValue = computeVoteValue(candidate);
        // The vote count is the decrypted aggregated value divided by the candidate’s vote value.
        int64_t voteCount = (voteValue != 0) ? (aggregatedValue / voteValue) : 0;

        cout << "Candidate " << candidate << " has " << voteCount << " votes." << endl;
    }

    return 0;
}
