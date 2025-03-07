/*! @file voting_proof.c
 *  @brief Modular functions to generate and verify a ZKP proof for an encrypted vote.
 *
 *  Instead of passing the encrypted vote as a command-line argument, we now read it from a file.
 */

 #include "picnic.h"
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <inttypes.h>
 
 #define DEFAULT_PARAMETER_SET Picnic_L1_FS
 
 // Helper: Read encrypted vote from a file
 char* read_encrypted_vote_from_file(const char* file_path) {
     FILE* file = fopen(file_path, "r");
     if (!file) {
         fprintf(stderr, "Error: Failed to open encrypted vote file: %s\n", file_path);
         return NULL;
     }
 
     // Get file size
     fseek(file, 0, SEEK_END);
     long file_size = ftell(file);
     rewind(file);
 
     // Allocate buffer
     char* encrypted_vote = malloc(file_size + 1);
     if (!encrypted_vote) {
         fprintf(stderr, "Error: Memory allocation failed for encrypted vote.\n");
         fclose(file);
         return NULL;
     }
 
     fread(encrypted_vote, 1, file_size, file);
     encrypted_vote[file_size] = '\0'; // Null-terminate the string
 
     fclose(file);
     return encrypted_vote;
 }
 
 // Helper: Convert a byte array to a hex string
 char* bytes_to_hex(const uint8_t* bytes, size_t len) {
     char* hexstr = malloc(len * 2 + 1);
     if (!hexstr) return NULL;
 
     for (size_t i = 0; i < len; i++) {
         sprintf(hexstr + i * 2, "%02x", bytes[i]);
     }
     hexstr[len * 2] = '\0';
     return hexstr;
 }
 
 // Helper: Convert a hex string to a byte array
 uint8_t* hex_to_bytes(const char* hex, size_t* out_len) {
     size_t hex_len = strlen(hex);
     if (hex_len % 2 != 0) return NULL;
 
     *out_len = hex_len / 2;
     uint8_t* bytes = malloc(*out_len);
     if (!bytes) return NULL;
 
     for (size_t i = 0; i < *out_len; i++) {
         sscanf(hex + 2 * i, "%2hhx", &bytes[i]);
     }
     return bytes;
 }
 
 // Serialize public key
 int serialize_public_key(picnic_publickey_t* pk, picnic_params_t param, char** pubkey_hex) {
     uint8_t pk_buf[PICNIC_MAX_PUBLICKEY_SIZE];
     int ret = picnic_write_public_key(pk, pk_buf, sizeof(pk_buf));
     if (ret < 0) return ret;
 
     if (ret == 0) ret = PICNIC_MAX_PUBLICKEY_SIZE;
     *pubkey_hex = bytes_to_hex(pk_buf, ret);
     return 0;
 }
 
 // Deserialize public key
 int deserialize_public_key(const char* pubkey_hex, picnic_publickey_t* pk) {
     size_t pk_len;
     uint8_t* pk_buf = hex_to_bytes(pubkey_hex, &pk_len);
     if (!pk_buf) return -1;
 
     int ret = picnic_read_public_key(pk, pk_buf, pk_len);
     free(pk_buf);
     return ret;
 }
 
 // Generate vote proof
 int generate_vote_proof(picnic_privatekey_t* sk, const char* encrypted_vote,
                          picnic_params_t param, char** proof_hex) {
     size_t vote_len = strlen(encrypted_vote);
     size_t max_sig_size = picnic_signature_size(param);
     uint8_t* signature = malloc(max_sig_size);
     if (!signature) return -1;
 
     size_t sig_size = max_sig_size;
     int ret = picnic_sign(sk, (const uint8_t*)encrypted_vote, vote_len, signature, &sig_size);
     if (ret != 0) {
         free(signature);
         return ret;
     }
 
     *proof_hex = bytes_to_hex(signature, sig_size);
     free(signature);
     return 0;
 }
 
 // Verify vote proof
 int verify_vote_proof(picnic_publickey_t* pk, const char* encrypted_vote,
                        const char* proof_hex, picnic_params_t param) {
     size_t vote_len = strlen(encrypted_vote);
     size_t sig_size;
     uint8_t* signature = hex_to_bytes(proof_hex, &sig_size);
     if (!signature) return -1;
 
     int ret = picnic_verify(pk, (const uint8_t*)encrypted_vote, vote_len, signature, sig_size);
     free(signature);
     return ret;
 }
 
 int main(int argc, char** argv) {
     if (argc < 3) {
         printf("Usage:\n"
                "  To generate proof: %s gen <parameter_set> <encrypted_vote_file>\n"
                "  To verify proof:   %s verify <parameter_set> <encrypted_vote_file> <public_key_hex> <proof_hex>\n",
                argv[0], argv[0]);
         return -1;
     }
 
     char* mode = argv[1];
     picnic_params_t param = (picnic_params_t)atoi(argv[2]);
 
     if (strcmp(mode, "gen") == 0) {
         if (argc < 4) {
             fprintf(stderr, "Error: In gen mode, provide the encrypted vote file path.\n");
             return -1;
         }
         const char* encrypted_vote_file = argv[3];
 
         // Read encrypted vote from file
         char* encrypted_vote = read_encrypted_vote_from_file(encrypted_vote_file);
         if (!encrypted_vote) return -1;
 
         printf("Generating proof for encrypted vote from file: %s\n", encrypted_vote_file);
         printf("Using parameter set: %s\n", picnic_get_param_name(param));
 
         // Generate key pair
         picnic_publickey_t pk;
         picnic_privatekey_t sk;
         printf("Generating key pair...\n");
         int ret = picnic_keygen(param, &pk, &sk);
         if (ret != 0) {
             fprintf(stderr, "Key generation failed (error code %d)\n", ret);
             free(encrypted_vote);
             return ret;
         }
         printf("Key generation successful.\n");
 
         // Generate ZKP proof (signature)
         char* proof_hex = NULL;
         ret = generate_vote_proof(&sk, encrypted_vote, param, &proof_hex);
         if (ret != 0) {
             fprintf(stderr, "Failed to generate vote proof (error code %d)\n", ret);
             free(encrypted_vote);
             return ret;
         }
 
         // Serialize public key
         char* pubkey_hex = NULL;
         ret = serialize_public_key(&pk, param, &pubkey_hex);
         if (ret != 0) {
             fprintf(stderr, "Failed to serialize public key (error code %d)\n", ret);
             free(proof_hex);
             free(encrypted_vote);
             return ret;
         }
 
         printf("Generated ZKP proof (hex):\n%s\n", proof_hex);
         printf("Serialized public key (hex):\n%s\n", pubkey_hex);
 
         free(proof_hex);
         free(pubkey_hex);
         free(encrypted_vote);
     } else if (strcmp(mode, "verify") == 0) {
         if (argc < 6) {
             fprintf(stderr, "Error: In verify mode, provide <encrypted_vote_file> <public_key_hex> <proof_hex>\n");
             return -1;
         }
         const char* encrypted_vote_file = argv[3];
 
         // Read encrypted vote from file
         char* encrypted_vote = read_encrypted_vote_from_file(encrypted_vote_file);
         if (!encrypted_vote) return -1;
 
         const char* pubkey_hex = argv[4];
         const char* proof_hex = argv[5];
 
         printf("Verifying proof for encrypted vote from file: %s\n", encrypted_vote_file);
         printf("Using parameter set: %s\n", picnic_get_param_name(param));
 
         // Deserialize public key
         picnic_publickey_t pk;
         int ret = deserialize_public_key(pubkey_hex, &pk);
         if (ret != 0) {
             fprintf(stderr, "Failed to deserialize public key (error code %d)\n", ret);
             free(encrypted_vote);
             return ret;
         }
 
         // Verify proof
         ret = verify_vote_proof(&pk, encrypted_vote, proof_hex, param);
         free(encrypted_vote);
 
         if (ret != 0) {
             fprintf(stderr, "Proof verification failed (error code %d)\n", ret);
             return ret;
         }
 
         printf("Proof verification succeeded. The vote is valid.\n");
     } else {
         fprintf(stderr, "Unknown mode. Use 'gen' to generate a proof or 'verify' to verify one.\n");
         return -1;
     }
 
     return 0;
 }
 