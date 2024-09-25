#ifndef COMMON_H
#define COMMON_H

struct Transaction {
    unsigned char sender_public_key[32];               // Sender public key (32 bytes)
    unsigned char recipient_public_key[32];            // Recipient public key (32 bytes)
    unsigned char value_transferred[8];                // Value transferred (8 bytes)
    unsigned char nonce[16];                           // Nonce (random value) (16 bytes)
    unsigned char hash[32];                            // Transaction hash (32 bytes)
    unsigned char digital_signature[64];               // Digital signature (64 bytes)
    unsigned char last_sender_transaction_index[8];    // Last sender transaction index (8 bytes)
    unsigned char last_recipient_transaction_index[8]; // Last recipient transaction index (8 bytes)
    unsigned char new_sender_balance[8];               // New sender balance (8 bytes)
    unsigned char new_recipient_balance[8];            // New recipient balance (8 bytes)
    unsigned char index[8];                            // Transaction index (8 bytes)
};

int verify_signature(const unsigned char *signature, const unsigned char *message, size_t message_len, const unsigned char *public_key);
int hash_transaction(unsigned char *output_buffer, const struct Transaction *tx);
int bytes_to_hex_string(char* buffer, size_t buffer_size, const unsigned char* bytes, int num_bytes);
int hex_to_bytes(const char *hex_str, unsigned char *byte_array, size_t byte_array_size);

#endif // COMMON_H

