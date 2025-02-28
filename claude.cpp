#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include "openfhe.h"

using namespace std;
using namespace lbcrypto;

// OpenFHE context and keys
CryptoContext<DCRTPoly> cryptoContext;
KeyPair<DCRTPoly> keyPair;

// Initialize OpenFHE with BFV scheme
void initializeOpenFHE() {
    // Set CryptoContext parameters for BFV scheme
    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetPlaintextModulus(65537);
    parameters.SetMultiplicativeDepth(1);
    
    // Generate crypto context
    cryptoContext = GenCryptoContext(parameters);
    
    // Enable features
    cryptoContext->Enable(PKE);
    cryptoContext->Enable(KEYSWITCH);
    cryptoContext->Enable(LEVELEDSHE);
    
    // Generate key pair
    keyPair = cryptoContext->KeyGen();
    
    cout << "OpenFHE context and keys initialized successfully" << endl;
}

// Serialize ciphertext to string and convert to hex
string encryptAndSerialize(const string& candidateId) {
    try {
        // Convert candidate ID to integer
        int64_t voteValue;
        try {
            // If candidateId is a UUID, hash it to an integer
            if (candidateId.size() > 10) {
                hash<string> hasher;
                voteValue = static_cast<int64_t>(hasher(candidateId) % 1000);
            } else {
                voteValue = stoll(candidateId);
            }
        } catch (...) {
            // Default if conversion fails
            voteValue = 1;
        }
        
        // Pack the vote value into a vector
        vector<int64_t> voteVector = {voteValue};
        
        // Create a plaintext object
        Plaintext plaintext = cryptoContext->MakePackedPlaintext(voteVector);
        
        // Encrypt the plaintext using the public key
        auto ciphertext = cryptoContext->Encrypt(keyPair.publicKey, plaintext);
        
        // Serialize the ciphertext to binary
        stringstream os;
        Serial::Serialize(ciphertext, os, SerType::BINARY);
        
        // Convert binary to hex for display
        stringstream hexStream;
        hexStream << std::hex << std::setfill('0');
        string serializedData = os.str();
        for (unsigned char c : serializedData) {
            hexStream << std::setw(2) << static_cast<int>(c);
        }
        
        return hexStream.str();
    }
    catch (const exception& e) {
        cerr << "Error encrypting vote: " << e.what() << endl;
        return "ERROR: " + string(e.what());
    }
}

int main(int argc, char* argv[]) {
    try {
        // Check if command-line argument is provided
        if (argc < 2) {
            cout << "Usage: " << argv[0] << " <candidate_id>" << endl;
            return 1;
        }
        
        string candidateId = argv[1];
        string publicKey = (argc > 2) ? argv[2] : "default_key";
        
        cout << "Initializing OpenFHE..." << endl;
        initializeOpenFHE();
        
        cout << "Encrypting vote for candidate ID: " << candidateId << endl;
        string encryptedVote = encryptAndSerialize(candidateId);
        
        cout << "=== ENCRYPTED VOTE DATA ===" << endl;
        cout << encryptedVote << endl;
        cout << "==========================" << endl;
        
        return 0;
    }
    catch (const exception& e) {
        cerr << "Fatal error: " << e.what() << endl;
        return 1;
    }
}


