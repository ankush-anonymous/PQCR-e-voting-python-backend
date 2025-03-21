#include <iostream>
#include <sstream>
#include <string>
#include <iomanip>
#include <functional>
#include <fstream>
#include <filesystem>  // Requires C++17
#include "openfhe.h"

using namespace std;
using namespace lbcrypto;

// Simple Base64 encoding function.
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

int main(int argc, char* argv[]) {
    // Check if the election id is provided.
    if (argc < 2) {
        cout << "Usage: " << argv[0] << " <election_id>" << endl;
        return 1;
    }
    string electionId = argv[1];

    // Create the "elections" directory if it does not exist.
    std::filesystem::create_directory("elections");

    // Initialize OpenFHE context with BFV scheme parameters.
    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetPlaintextModulus(65537);
    parameters.SetMultiplicativeDepth(1);
    
    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);
    cryptoContext->Enable(PKE);
    cryptoContext->Enable(KEYSWITCH);
    cryptoContext->Enable(LEVELEDSHE);
    
    // Save the crypto context to file.
    cout << "Serializing crypto context to file..." << endl;
    try {
        if (!Serial::SerializeToFile("cryptocontext.txt", cryptoContext, SerType::BINARY)) {
            cerr << "Error: Failed to serialize crypto context to file." << endl;
            return 1;
        }
        cout << "Crypto context successfully saved to cryptocontext.txt" << endl;
        
        // Verify by trying to load it back.
        CryptoContext<DCRTPoly> loadedContext;
        if (!Serial::DeserializeFromFile("cryptocontext.txt", loadedContext, SerType::BINARY)) {
            cerr << "Error: Failed to deserialize the crypto context we just saved." << endl;
            return 1;
        }
        cout << "Successfully verified the serialized context can be loaded back." << endl;
    } catch (const exception& e) {
        cerr << "Exception during serialization: " << e.what() << endl;
        return 1;
    }

    // Generate key pair.
    KeyPair<DCRTPoly> keyPair = cryptoContext->KeyGen();
    if (!keyPair.good()) {
        cerr << "Key generation failed" << endl;
        return 1;
    }
    cout << "Keys generated successfully." << endl;
    
    // Serialize public key.
    stringstream publicStream;
    Serial::Serialize(keyPair.publicKey, publicStream, SerType::BINARY);
    string publicStr = publicStream.str();
    
    // Serialize private key.
    stringstream privateStream;
    Serial::Serialize(keyPair.secretKey, privateStream, SerType::BINARY);
    string privateStr = privateStream.str();
    
    // Save raw keys (binary) to files without Base64 conversion.
    string pubKeyFilename = "elections/" + electionId + "_public_key.tmp";
    string privKeyFilename = "elections/" + electionId + "_priv_key.tmp";
    
    ofstream pubFile(pubKeyFilename, ios::binary);
    if (!pubFile.is_open()) {
        cerr << "Error: Could not open file " << pubKeyFilename << " for writing." << endl;
        return 1;
    }
    pubFile.write(publicStr.data(), publicStr.size());
    pubFile.close();
    
    ofstream privFile(privKeyFilename, ios::binary);
    if (!privFile.is_open()) {
        cerr << "Error: Could not open file " << privKeyFilename << " for writing." << endl;
        return 1;
    }
    privFile.write(privateStr.data(), privateStr.size());
    privFile.close();

    // Convert keys to Base64.
    string publicKeyBase64 = base64Encode(publicStr);
    string privateKeyBase64 = base64Encode(privateStr);

    // Output Base64 keys.
    cout << "Public Key (Base64):" << endl;
    cout << publicKeyBase64 << endl << endl;
    
    cout << "Private Key (Base64):" << endl;
    cout << privateKeyBase64 << endl;
    
    return 0;
}
