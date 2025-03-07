#include "picnic.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>

#define DEFAULT_PARAMETER_SET Picnic_L1_FS

char* read_encrypted_vote_from_file(const char* file_path) {
    FILE* file = fopen(file_path, "r");
    if (!file) {
        fprintf(stderr, "Error: Cannot open file %s\n", file_path);
        return NULL;
    }
    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    rewind(file);
    char* data = malloc(size + 1);
    if (!data) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        fclose(file);
        return NULL;
    }
    fread(data, 1, size, file);
    data[size] = '\0';
    fclose(file);
    return data;
}

uint8_t* base64_to_bytes(const char* base64, size_t* out_len) {
    BIO *bio, *b64;
    size_t len = strlen(base64);
    uint8_t* buffer = malloc(len);
    if (!buffer) return NULL;
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_mem_buf(base64, -1);
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    *out_len = BIO_read(bio, buffer, len);
    BIO_free_all(bio);
    return buffer;
}

char* bytes_to_base64(const uint8_t* bytes, size_t len) {
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;
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

int verify_vote_proof(picnic_publickey_t* pk, const uint8_t* encrypted_vote,
                      size_t vote_len, const char* proof_base64, picnic_params_t param) {
    size_t sig_size;
    uint8_t* signature = base64_to_bytes(proof_base64, &sig_size);
    if (!signature) return -1;
    int ret = picnic_verify(pk, encrypted_vote, vote_len, signature, sig_size);
    free(signature);
    return ret;
}

char* export_public_key(picnic_publickey_t* pk, picnic_params_t param) {
    size_t pk_struct_size = sizeof(picnic_publickey_t);
    uint8_t* serialized = malloc(4 + pk_struct_size);
    if (!serialized) return NULL;
    memcpy(serialized, &param, 4);
    memcpy(serialized + 4, pk, pk_struct_size);
    char* base64 = bytes_to_base64(serialized, 4 + pk_struct_size);
    free(serialized);
    return base64;
}

int import_public_key(picnic_publickey_t* pk, const char* base64) {
    size_t binary_len;
    uint8_t* binary = base64_to_bytes(base64, &binary_len);
    if (!binary || binary_len < 4 + sizeof(picnic_publickey_t)) {
        free(binary);
        return -1;
    }
    memcpy(pk, binary + 4, sizeof(picnic_publickey_t));
    free(binary);
    return 0;
}

int main(int argc, char** argv) {
    if (argc < 3) {
        printf("Usage:\n  %s gen <parameter_set> <encrypted_vote_file>\n"
               "  %s verify <parameter_set> <encrypted_vote_file> <public_key_base64> <proof_base64>\n",
               argv[0], argv[0]);
        return -1;
    }
    char* mode = argv[1];
    picnic_params_t param = (picnic_params_t)atoi(argv[2]);

    if (strcmp(mode, "gen") == 0) {
        if (argc < 4) {
            fprintf(stderr, "Error: Encrypted vote file path required for gen mode.\n");
            return -1;
        }
        const char* file_path = argv[3];
        char* vote_b64 = read_encrypted_vote_from_file(file_path);
        if (!vote_b64) return -1;
        size_t vote_len;
        uint8_t* vote = base64_to_bytes(vote_b64, &vote_len);
        free(vote_b64);
        if (!vote) return -1;
        picnic_publickey_t pk;
        picnic_privatekey_t sk;
        int ret = picnic_keygen(param, &pk, &sk);
        if (ret != 0) {
            fprintf(stderr, "Error: Key generation failed (code %d)\n", ret);
            free(vote);
            return ret;
        }
        char* pk_b64 = export_public_key(&pk, param);
        if (!pk_b64) {
            fprintf(stderr, "Error: Failed to export public key.\n");
            free(vote);
            return -1;
        }
        char* proof_b64 = NULL;
        ret = generate_vote_proof(&sk, vote, vote_len, param, &proof_b64);
        free(vote);
        if (ret != 0) {
            fprintf(stderr, "Error: Failed to generate vote proof (code %d)\n", ret);
            free(pk_b64);
            return ret;
        }
        printf("Serialized public key (Base64):\n%s\n", pk_b64);
        printf("Generated ZKP proof (Base64):\n%s\n", proof_b64);
        free(proof_b64);
        free(pk_b64);
    } else if (strcmp(mode, "verify") == 0) {
        if (argc < 6) {
            fprintf(stderr, "Error: Provide encrypted_vote_file, public_key_base64, and proof_base64 for verify mode.\n");
            return -1;
        }
        const char* file_path = argv[3];
        const char* pk_b64 = argv[4];
        const char* proof_b64 = argv[5];
        char* vote_b64 = read_encrypted_vote_from_file(file_path);
        if (!vote_b64) return -1;
        size_t vote_len;
        uint8_t* vote = base64_to_bytes(vote_b64, &vote_len);
        free(vote_b64);
        if (!vote) return -1;
        picnic_publickey_t pk;
        int ret = import_public_key(&pk, pk_b64);
        if (ret != 0) {
            fprintf(stderr, "Error: Failed to import public key.\n");
            free(vote);
            return -1;
        }
        ret = verify_vote_proof(&pk, vote, vote_len, proof_b64, param);
        free(vote);
        if (ret != 0) {
            fprintf(stderr, "Error: Proof verification failed (code %d)\n", ret);
            return ret;
        }
        printf("Proof verification succeeded.\n");
    } else {
        fprintf(stderr, "Error: Unknown mode. Use 'gen' or 'verify'.\n");
        return -1;
    }
    return 0;
}
