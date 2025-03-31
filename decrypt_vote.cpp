#include <openfhe.h>
#include <filesystem>
#include <iostream>
#include <fstream>
#include <stdexcept>
#include <string>
#include <vector>

using namespace lbcrypto;
using namespace std;
namespace fs = std::filesystem;

int main(int argc, char* argv[]) {
    if (argc != 2) {
        cerr << "Usage: " << argv[0] << " <election_id>" << endl;
        return 1;
    }

    string electionId = argv[1];
    string credentialsFolder = electionId + "_credentials/";
    string contextFile = credentialsFolder + "cryptocontext.bin";
    string privateKeyFile = credentialsFolder + "private_key.bin";
    string aggregatedFile = "encrypted_votes/aggregated_vote.bin";

    // Deserialize crypto context
    CryptoContext<DCRTPoly> cc;
    if (!Serial::DeserializeFromFile(contextFile, cc, SerType::BINARY)) {
        cerr << "Failed to deserialize crypto context" << endl;
        return 1;
    }

    // Deserialize private key
    PrivateKey<DCRTPoly> privateKey;
    if (!Serial::DeserializeFromFile(privateKeyFile, privateKey, SerType::BINARY)) {
        cerr << "Failed to deserialize private key" << endl;
        return 1;
    }

    // Deserialize ciphertext
    Ciphertext<DCRTPoly> aggregatedVote;
    if (!Serial::DeserializeFromFile(aggregatedFile, aggregatedVote, SerType::BINARY)) {
        cerr << "Failed to deserialize aggregated vote" << endl;
        return 1;
    }

    cout << "Original context match? " 
         << std::boolalpha 
         << (aggregatedVote->GetCryptoContext() == cc) 
         << endl;

    // Fix the ciphertext by associating it with cc
    // Create a zero plaintext with the same ring dimension
    vector<int64_t> zeroVector(cc->GetRingDimension(), 0);
    Plaintext zeroPt = cc->MakeCoefPackedPlaintext(zeroVector);

    // Perform a trivial EvalAdd to associate the ciphertext with cc
    Ciphertext<DCRTPoly> fixedVote = cc->EvalAdd(aggregatedVote, zeroPt);

    cout << "Fixed context match? " 
         << std::boolalpha 
         << (fixedVote->GetCryptoContext() == cc) 
         << endl;

    // Decrypt with exception handling
    try {
        Plaintext decryptedResult;
        cc->Decrypt(privateKey, fixedVote, &decryptedResult);
        cout << "Decrypted result: " << decryptedResult << endl;
    } catch (const exception& e) {
        cerr << "Decryption failed: " << e.what() << endl;
        return 1;
    }

    return 0;
}