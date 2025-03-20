#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include "openfhe.h"
#include <nlohmann/json.hpp>
#include <exception>

using namespace std;
using namespace lbcrypto;
using json = nlohmann::json;

int main(int argc, char* argv[]) {
    // (Optional) Register all serializable types if needed.
    // Serial::RegisterAllPalisadeSerialization();  // Uncomment if available/required

    if (argc != 2) {
        cerr << "Usage: " << argv[0] << " <votes_file>" << endl;
        return 1;
    }
    string votesFile = argv[1];
    string outputFile = votesFile.substr(0, votesFile.find_last_of('.')) + "_aggregated_result.json";
    
    // Read votes from JSON file
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
    
    // Deserialize crypto context
    cout << "Deserializing crypto context..." << endl;
    CryptoContext<DCRTPoly> cc;
    if (!Serial::DeserializeFromFile("cryptocontext.txt", cc, SerType::BINARY)) {
        cerr << "Error: Could not load crypto context." << endl;
        return 1;
    }
    
    // Process votes
    vector<string> encryptedVotes;
    try {
        for (const auto& voteObj : votesJson["votes"]) {
            encryptedVotes.push_back(voteObj["encrypted_vote"]);
        }
    } catch (const exception& e) {
        cerr << "Error extracting votes: " << e.what() << endl;
        return 1;
    }
    
    cout << "Processing " << encryptedVotes.size() << " votes..." << endl;
    
    // Deserialize the first vote to initialize aggregation
    if (encryptedVotes.empty()) {
        cerr << "Error: No votes found." << endl;
        return 1;
    }
    
    Ciphertext<DCRTPoly> aggregatedVote;
    bool firstVote = true;
    
    for (const auto& encVote : encryptedVotes) {
        Ciphertext<DCRTPoly> currVote;
        istringstream iss(encVote);
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
    
    // Serialize the final aggregated ciphertext
    ostringstream oss;
    try {
        Serial::Serialize(aggregatedVote, oss, SerType::BINARY);
    } catch (const exception& e) {
        cerr << "Error serializing aggregated vote: " << e.what() << endl;
        return 1;
    }
    string serializedResult = oss.str();
    
    // Output results to file
    ofstream outFile(outputFile);
    if (!outFile.is_open()) {
        cerr << "Error: Could not open output file." << endl;
        return 1;
    }
    
    json resultJson;
    resultJson["total_votes"] = encryptedVotes.size();
    resultJson["aggregated_encrypted_vote"] = serializedResult;
    
    outFile << resultJson.dump(4); // Pretty print with 4-space indent
    outFile.close();
    
    cout << "Vote aggregation complete. Encrypted result saved to " << outputFile << endl;
    
    return 0;
}
