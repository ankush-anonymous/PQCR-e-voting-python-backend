#include <openfhe.h>
#include <filesystem>
#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <stdexcept>

#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/bfvrns/bfvrns-ser.h"


using namespace lbcrypto;
using namespace std;
namespace fs = std::filesystem;

int main(int argc, char* argv[]) {
    // Expected usage: ./aggregator <election_id>
    if (argc != 2) {
        cerr << "Usage: " << argv[0] << " <election_id>" << endl;
        return 1;
    }
    
    string electionId = argv[1];
    
    // Construct file paths for the crypto context.
    string credentialsFolder = electionId + "_credentials/";
    string contextFile = credentialsFolder + "cryptocontext.bin";
    string privateKeyFile = credentialsFolder + "private_key.bin";
    
    // Deserialize crypto context.
    CryptoContext<DCRTPoly> cc;
    if (!Serial::DeserializeFromFile(contextFile, cc, SerType::BINARY)) {
        cerr << "Failed to deserialize crypto context" << endl;
        return 1;
    }
    // Enable necessary features (must match keygen).
    // cc->Enable(PKE);
    // cc->Enable(KEYSWITCH);
    // cc->Enable(LEVELEDSHE);

    // Deserialize private key
    PrivateKey<DCRTPoly> privateKey;
    if (!Serial::DeserializeFromFile(privateKeyFile, privateKey, SerType::BINARY)) {
        cerr << "Failed to deserialize private key" << endl;
        return 1;
    }


   
    // Directory containing encrypted vote files.
    string votesFolder = "encrypted_votes/";
    if (!fs::exists(votesFolder)) {
        cerr << "Votes folder does not exist: " << votesFolder << endl;
        return 1;
    }
    
    Ciphertext<DCRTPoly> aggregatedVote;
    bool firstVote = true;
    int voteCount = 0;
    
    // Suffix to match.
    const string suffix = "_encrypted_vote.bin"; // 19 characters
    
    // Iterate over files in the votes folder.
    for (const auto& entry : fs::directory_iterator(votesFolder)) {
        if (entry.is_regular_file()) {
            string filePath = entry.path().string();
            // Check if the filename ends with the required suffix.
            if (filePath.size() >= suffix.size() && filePath.substr(filePath.size() - suffix.size()) == suffix) {
                cout << "Processing file: " << filePath << endl;
                Ciphertext<DCRTPoly> currVote;
                if (!Serial::DeserializeFromFile(filePath, currVote, SerType::BINARY)) {
                    cerr << "Failed to deserialize vote from file: " << filePath << endl;
                    continue; // Optionally, you can exit here instead.
                }
                if (firstVote) {
                    aggregatedVote = currVote;
                    firstVote = false;
                } else {
                    aggregatedVote = cc->EvalAdd(aggregatedVote, currVote);
                }
                voteCount++;
            }
        }
    }
    
    if (voteCount == 0) {
        cerr << "No encrypted votes found in " << votesFolder << endl;
        return 1;
    }

    try {
        Plaintext decryptedResult;
        cc->Decrypt(privateKey, aggregatedVote, &decryptedResult);
        
        // Get the complete decrypted vector
        const vector<int64_t>& votes = decryptedResult->GetCoefPackedValue();
        
        // Print full vector without truncation
        cout << "Decrypted result: [";
        for (size_t i = 0; i < votes.size(); ++i) {
            cout << votes[i];
            if (i != votes.size() - 1) {
                cout << ", ";
            }
            // Add line breaks for readability (every 16 elements)
            if ((i + 1) % 16 == 0) cout << "\n ";
        }
        cout << "]" << endl;
        
    } catch (const exception& e) {
        cerr << "Decryption failed: " << e.what() << endl;
        return 1;
    }

    
    // Save aggregated vote to a file.
    string aggregatedFile = votesFolder + "aggregated_vote.bin";
    if (!Serial::SerializeToFile(aggregatedFile, aggregatedVote, SerType::BINARY)) {
        cerr << "Failed to serialize aggregated vote to " << aggregatedFile << endl;
        return 1;
    }
    
    cout << "Aggregated " << voteCount << " votes and saved the result to " << aggregatedFile << endl;

    cout << "Associated context match? " 
    << std::boolalpha 
    << (aggregatedVote->GetCryptoContext() == cc) 
    << endl;
    
    return 0;
}
