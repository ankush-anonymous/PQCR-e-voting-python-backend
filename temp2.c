/*! @file voting_proof.c
 *  @brief Modular functions to generate and verify a ZKP proof for an encrypted vote.
 *
 *  Now reads the encrypted vote from a file (Base64), decodes it, and processes it.
 */

 #include "picnic.h"
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <inttypes.h>
 #include <openssl/bio.h>
 #include <openssl/evp.h>
 #include <openssl/buffer.h>
 
 #define DEFAULT_PARAMETER_SET Picnic_L1_FS
 
 // Helper: Log file path for debugging
 void log_file_path(const char* file_path) {
     printf("[LOG] Reading encrypted vote from file: %s\n", file_path);
 }
 
 // Helper: Read encrypted vote (Base64) from a file
 char* read_encrypted_vote_from_file(const char* file_path) {
     printf("[DEBUG] Trying to open file: %s\n", file_path);
     FILE* file = fopen(file_path, "r");
     if (!file) {
         fprintf(stderr, "[ERROR] Failed to open encrypted vote file: %s\n", file_path);
         return NULL;
     }
 
     fseek(file, 0, SEEK_END);
     long file_size = ftell(file);
     rewind(file);
 
     char* encrypted_vote = malloc(file_size + 1);
     if (!encrypted_vote) {
         fprintf(stderr, "[ERROR] Memory allocation failed for encrypted vote.\n");
         fclose(file);
         return NULL;
     }
 
     fread(encrypted_vote, 1, file_size, file);
     encrypted_vote[file_size] = '\0';
     fclose(file);
 
     printf("[DEBUG] Successfully read encrypted vote from file\n");
     return encrypted_vote;
 }
 
 // Helper: Decode Base64 to bytes
 uint8_t* base64_to_bytes(const char* base64, size_t* out_len) {
     BIO* bio, * b64;
     size_t base64_len = strlen(base64);
     uint8_t* bytes = malloc(base64_len);
     if (!bytes) return NULL;
 
     b64 = BIO_new(BIO_f_base64());
     bio = BIO_new_mem_buf(base64, -1);
     bio = BIO_push(b64, bio);
 
     BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
     *out_len = BIO_read(bio, bytes, base64_len);
 
     BIO_free_all(bio);
     return bytes;
 }
 
 // Helper: Encode bytes to Base64
 char* bytes_to_base64(const uint8_t* bytes, size_t len) {
     BIO* bio, * b64;
     BUF_MEM* bufferPtr;
 
     b64 = BIO_new(BIO_f_base64());
     bio = BIO_new(BIO_s_mem());
     bio = BIO_push(b64, bio);
 
     BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
     BIO_write(bio, bytes, len);
     BIO_flush(bio);
     BIO_get_mem_ptr(bio, &bufferPtr);
 
     char* base64str = malloc(bufferPtr->length + 1);
     if (!base64str) {
         BIO_free_all(bio);
         return NULL;
     }
 
     memcpy(base64str, bufferPtr->data, bufferPtr->length);
     base64str[bufferPtr->length] = '\0';
 
     BIO_free_all(bio);
     return base64str;
 }
 
 // Generate vote proof
 int generate_vote_proof(picnic_privatekey_t* sk, const uint8_t* encrypted_vote,
                          size_t vote_len, picnic_params_t param, char** proof_base64) {
     size_t max_sig_size = picnic_signature_size(param);
     uint8_t* signature = malloc(max_sig_size);
     if (!signature) return -1;
 
     size_t sig_size = max_sig_size;
     int ret = picnic_sign(sk, encrypted_vote, vote_len, signature, &sig_size);
     if (ret != 0) {
         free(signature);
         return ret;
     }
 
     *proof_base64 = bytes_to_base64(signature, sig_size);
     free(signature);
     return 0;
 }
 
 // Verify vote proof
 int verify_vote_proof(picnic_publickey_t* pk, const uint8_t* encrypted_vote,
                        size_t vote_len, const char* proof_base64, picnic_params_t param) {
     size_t sig_size;
     uint8_t* signature = base64_to_bytes(proof_base64, &sig_size);
     if (!signature) return -1;
 
     int ret = picnic_verify(pk, encrypted_vote, vote_len, signature, sig_size);
     free(signature);
     return ret;
 }
 
 int main(int argc, char** argv) {
     if (argc < 3) {
         printf("Usage:\n"
                "  To generate proof: %s gen <parameter_set> <encrypted_vote_file>\n"
                "  To verify proof:   %s verify <parameter_set> <encrypted_vote_file> <public_key_base64> <proof_base64>\n",
                argv[0], argv[0]);
         return -1;
     }
 
     char* mode = argv[1];
     picnic_params_t param = (picnic_params_t)atoi(argv[2]);
 
     if (strcmp(mode, "gen") == 0) {
         if (argc < 4) {
             fprintf(stderr, "[ERROR] In gen mode, provide the encrypted vote file path.\n");
             return -1;
         }
         const char* encrypted_vote_file = argv[3];
 
         // Log file path
         log_file_path(encrypted_vote_file);
 
         // Read encrypted vote from file
         char* encrypted_vote_base64 = read_encrypted_vote_from_file(encrypted_vote_file);
         if (!encrypted_vote_base64) return -1;
 
         size_t vote_len;
         uint8_t* encrypted_vote = base64_to_bytes(encrypted_vote_base64, &vote_len);
         free(encrypted_vote_base64);
         if (!encrypted_vote) return -1;
 
         printf("[LOG] Generating proof for encrypted vote from file: %s\n", encrypted_vote_file);
 
         // Generate key pair
         picnic_publickey_t pk;
         picnic_privatekey_t sk;
         printf("[LOG] Generating key pair...\n");
         int ret = picnic_keygen(param, &pk, &sk);
         if (ret != 0) {
             fprintf(stderr, "[ERROR] Key generation failed (error code %d)\n", ret);
             free(encrypted_vote);
             return ret;
         }
         printf("[LOG] Key generation successful.\n");
 
         // Generate ZKP proof
         char* proof_base64 = NULL;
         ret = generate_vote_proof(&sk, encrypted_vote, vote_len, param, &proof_base64);
         free(encrypted_vote);
         if (ret != 0) {
             fprintf(stderr, "[ERROR] Failed to generate vote proof (error code %d)\n", ret);
             return ret;
         }
 
         printf("[LOG] Generated ZKP proof (Base64):\n%s\n", proof_base64);
 
         free(proof_base64);
     } else if (strcmp(mode, "verify") == 0) {
         if (argc < 6) {
             fprintf(stderr, "[ERROR] In verify mode, provide <encrypted_vote_file> <public_key_base64> <proof_base64>\n");
             return -1;
         }
         const char* encrypted_vote_file = argv[3];
 
         // Read encrypted vote from file
         char* encrypted_vote_base64 = read_encrypted_vote_from_file(encrypted_vote_file);
         if (!encrypted_vote_base64) return -1;
 
         size_t vote_len;
         uint8_t* encrypted_vote = base64_to_bytes(encrypted_vote_base64, &vote_len);
         free(encrypted_vote_base64);
         if (!encrypted_vote) return -1;
 
         const char* proof_base64 = argv[5];
 
         printf("[LOG] Verifying proof for encrypted vote from file: %s\n", encrypted_vote_file);
 
         // Verify proof
         int ret = verify_vote_proof(NULL, encrypted_vote, vote_len, proof_base64, param);
         free(encrypted_vote);
 
         if (ret != 0) {
             fprintf(stderr, "[ERROR] Proof verification failed (error code %d)\n", ret);
             return ret;
         }
 
         printf("[LOG] Proof verification succeeded. The vote is valid.\n");
     } else {
         fprintf(stderr, "[ERROR] Unknown mode. Use 'gen' to generate a proof or 'verify' to verify one.\n");
         return -1;
     }
 
     return 0;
 }
 