#include <stdio.h>
#include <string.h>
#include "common.h"

int compute_sha256_hash(unsigned char *output_buffer, const unsigned char *input_data, size_t input_length) {
    // Ensure libsodium is initialized
    if (sodium_init() < 0) {
        fprintf(stderr, "libsodium initialization failed\n");
        return -1;
    }

    // Compute the SHA256 hash
    if (crypto_hash_sha256(output_buffer, input_data, input_length) != 0) {
        fprintf(stderr, "Hash computation failed\n");
        return -1;
    }

    return 0; // Success
}

int generate_key_pair(unsigned char *public_key, unsigned char *private_key) {
    // Ensure libsodium is initialized
    if (sodium_init() < 0) {
        fprintf(stderr, "libsodium initialization failed\n");
        return -1;
    }

    // Generate the key pair
    if (crypto_sign_keypair(public_key, private_key) != 0) {
        fprintf(stderr, "Key pair generation failed\n");
        return -1;
    }

    return 0;
}

int sign_message(const unsigned char *message, size_t message_len, const unsigned char *private_key, unsigned char *signature) {
    unsigned long long signature_len;

    // Ensure libsodium is initialized
    if (sodium_init() < 0) {
        fprintf(stderr, "libsodium initialization failed\n");
        return -1;
    }

    // Sign the message
    if (crypto_sign_detached(signature, &signature_len, message, message_len, private_key) != 0) {
        fprintf(stderr, "Message signing failed\n");
        return -1;
    }

    return 0;
}

int verify_signature(const unsigned char *signature, const unsigned char *message, size_t message_len, const unsigned char *public_key) {
    // Ensure libsodium is initialized
    if (sodium_init() < 0) {
        fprintf(stderr, "libsodium initialization failed\n");
        return -1;
    }

    // Verify the signature
    if (crypto_sign_verify_detached(signature, message, message_len, public_key) != 0) {
        // Signature is invalid
        return -1;
    }

    return 0; // Signature is valid
}

int hash_transaction_fields(unsigned char *output_buffer, const struct Transaction *tx) {
    // Buffer to hold the concatenated fields
    unsigned char concatenated_data[32 + 32 + 8 + 8 + 8 + 8];
    unsigned long long offset = 0;

    // Copy each field into the buffer
    memcpy(concatenated_data + offset, tx->sender_public_key, 32);
    offset += 32;
    memcpy(concatenated_data + offset, tx->recipient_public_key, 32);
    offset += 32;
    memcpy(concatenated_data + offset, tx->last_sender_transaction_index, 8);
    offset += 8;
    memcpy(concatenated_data + offset, tx->last_recipient_transaction_index, 8);
    offset += 8;
    memcpy(concatenated_data + offset, tx->new_sender_balance, 8);
    offset += 8;
    memcpy(concatenated_data + offset, tx->new_recipient_balance, 8);

    // Compute the hash of the concatenated data
    return compute_sha256_hash(output_buffer, concatenated_data, sizeof(concatenated_data));
}

