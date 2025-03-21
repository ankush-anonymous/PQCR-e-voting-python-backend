#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include "openfhe.h"
#include <nlohmann/json.hpp>
#include <exception>
#include <algorithm>

using namespace std;
using namespace lbcrypto;
using json = nlohmann::json;

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
    // (Optional) Register all serializable types if needed.
    // Serial::RegisterAllPalisadeSerialization();  // Uncomment if your version requires it

    if (argc != 2) {
        cerr << "Usage: " << argv[0] << " <votes_file>" << endl;
        return 1;
    }
    string votesFile = argv[1];
    string outputFile = votesFile.substr(0, votesFile.find_last_of('.')) + "_aggregated_result.json";

    // Read votes from JSON file.
    cout << "Reading votes from " << votesFile << endl;
    ifstream votesStream(votesFile);
    if (!votesStream.is_open()) {
        cerr << "Error: Could not open votes file." << endl;
        return 1;
    }

    json votesJson;
    try {
        votesStream >> votesJson;
    } catch (const exception& e) {
        cerr << "Error parsing JSON: " << e.what() << endl;
        return 1;
    }
    votesStream.close();

    // Deserialize crypto context.
    cout << "Deserializing crypto context..." << endl;
    CryptoContext<DCRTPoly> cc;
    if (!Serial::DeserializeFromFile("cryptocontext.txt", cc, SerType::BINARY)) {
        cerr << "Error: Could not load crypto context." << endl;
        return 1;
    }

    // Extract encrypted votes from JSON.
    vector<string> encryptedVotes;
    try {
        for (const auto& voteObj : votesJson["votes"]) {
            encryptedVotes.push_back(voteObj["encrypted_vote"].get<string>());
        }
    } catch (const exception& e) {
        cerr << "Error extracting votes: " << e.what() << endl;
        return 1;
    }

    cout << "Processing " << encryptedVotes.size() << " votes..." << endl;

    if (encryptedVotes.empty()) {
        cerr << "Error: No votes found." << endl;
        return 1;
    }

    // Aggregate votes using homomorphic addition.
    Ciphertext<DCRTPoly> aggregatedVote;
    bool firstVote = true;

    for (const auto& encVote : encryptedVotes) {
        Ciphertext<DCRTPoly> currVote;
        // Decode the Base64-encoded vote back into binary.
        string decodedVote = base64Decode(encVote);
        istringstream iss(decodedVote);
        try {
            Serial::Deserialize(currVote, iss, SerType::BINARY);
        } catch (const exception& e) {
            cerr << "Error deserializing a vote: " << e.what() << endl;
            return 1;
        }

        if (firstVote) {
            aggregatedVote = currVote;
            firstVote = false;
        } else {
            try {
                aggregatedVote = cc->EvalAdd(aggregatedVote, currVote);
            } catch (const exception& e) {
                cerr << "Error during vote aggregation: " << e.what() << endl;
                return 1;
            }
        }
    }

    // Serialize the final aggregated ciphertext.
    ostringstream oss;
    try {
        Serial::Serialize(aggregatedVote, oss, SerType::BINARY);
    } catch (const exception& e) {
        cerr << "Error serializing aggregated vote: " << e.what() << endl;
        return 1;
    }
    string serializedResult = oss.str();

    // Base64 encode the aggregated ciphertext so it is valid UTF-8 for JSON.
    string aggregatedCiphertextBase64 = base64Encode(serializedResult);

    // Output results to file.
    ofstream outFile(outputFile);
    if (!outFile.is_open()) {
        cerr << "Error: Could not open output file." << endl;
        return 1;
    }

    json resultJson;
    resultJson["total_votes"] = encryptedVotes.size();
    resultJson["aggregated_encrypted_vote"] = aggregatedCiphertextBase64;

    outFile << resultJson.dump(4); // Pretty print with 4-space indent.
    outFile.close();

    cout << "Vote aggregation complete. Encrypted result saved to " << outputFile << endl;

    return 0;
}
