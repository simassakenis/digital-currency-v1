#ifndef COMMON_H
#define COMMON_H

#include <sodium.h>
#include <stddef.h>

struct Transaction {
    unsigned char index[8];                            // Transaction index (8 bytes)
    unsigned char sender_public_key[32];               // Sender public key (32 bytes)
    unsigned char recipient_public_key[32];            // Recipient public key (32 bytes)
    unsigned char last_sender_transaction_index[8];    // Last sender transaction index (8 bytes)
    unsigned char last_recipient_transaction_index[8]; // Last recipient transaction index (8 bytes)
    unsigned char new_sender_balance[8];               // New sender balance (8 bytes)
    unsigned char new_recipient_balance[8];            // New recipient balance (8 bytes)
    unsigned char hash[32];                            // Transaction hash (32 bytes)
    unsigned char digital_signature[64];               // Digital signature (64 bytes)
};

int compute_sha256_hash(unsigned char *output_buffer, const unsigned char *input_data, size_t input_length);
int generate_key_pair(unsigned char *public_key, unsigned char *private_key);
int sign_message(const unsigned char *message, size_t message_len, const unsigned char *private_key, unsigned char *signature);
int verify_signature(const unsigned char *signature, const unsigned char *message, size_t message_len, const unsigned char *public_key);
int hash_transaction(unsigned char *output_buffer, const struct Transaction *tx);

#endif // COMMON_H

