#include <assert.h>
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <arpa/inet.h>

#define PORT 8080
#define REQUEST_BUFFER_SIZE 10240
#define RESPONSE_BUFFER_SIZE 10240
#define NUM_TRANSACTIONS_TO_SHOW 10
#define TRANSACTIONS_CACHE_SIZE 128
#define HASH_TABLE_SIZE 256

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

struct TransactionsCache {
    struct Transaction transactions[TRANSACTIONS_CACHE_SIZE];  // Array to hold 128 transactions
    int count;  // Number of transactions currently in the cache
};

int add_transaction_to_cache(struct TransactionsCache *cache, const struct Transaction *transaction) {
    if (cache->count < TRANSACTIONS_CACHE_SIZE) {
        cache->transactions[cache->count] = *transaction;  // Copy the transaction to the cache
        cache->count++;  // Increment the count
        return 0;  // Success
    } else {
        return -1;  // Cache is full, return an error
    }
}


// Hash table entry mapping a user public key to the last transaction index
struct HashTableEntry {
    unsigned char public_key[32];  // User's public key (32 bytes)
    unsigned char last_transaction_index[8];  // Index of the last transaction (8 bytes)
    struct HashTableEntry *next;  // Pointer to the next entry in case of a collision (chaining)
};

// Hash table structure
struct HashTable {
    struct HashTableEntry *entries[HASH_TABLE_SIZE];  // Array of pointers to linked lists
};

// Initialize the hash table
void init_hash_table(struct HashTable *table) {
    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        table->entries[i] = NULL;  // Initialize all entries to NULL
    }
}

// Simple hash function for 32-byte public keys
unsigned int hash_table_index(const unsigned char *public_key) {
    unsigned int index = 0;
    for (int i = 0; i < 32; i++) {
        // Multiply by 31 (a prime) for better distribution of hash values
        index = (index * 31) + public_key[i];
    }
    return index % HASH_TABLE_SIZE;
}

// Function to look up the last transaction index for a user (with chaining)
unsigned char *lookup(const struct HashTable *table, const unsigned char *public_key) {
    unsigned int index = hash_table_index(public_key);
    struct HashTableEntry *entry = table->entries[index];

    // Traverse the linked list to find the matching public key
    while (entry != NULL) {
        if (memcmp(entry->public_key, public_key, 32) == 0) {
            return entry->last_transaction_index;  // Return the last transaction index
        }
        entry = entry->next;  // Move to the next entry in the chain
    }

    return NULL;  // User not found
}

// Function to update the last transaction index for a user (with chaining)
void update(struct HashTable *table, const unsigned char *public_key, const unsigned char *last_transaction_index) {
    unsigned int index = hash_table_index(public_key);
    struct HashTableEntry *entry = table->entries[index];

    // Traverse the linked list to find the matching public key
    while (entry != NULL) {
        if (memcmp(entry->public_key, public_key, 32) == 0) {
            // Update existing entry
            memcpy(entry->last_transaction_index, last_transaction_index, 8);
            return;
        }
        entry = entry->next;  // Move to the next entry in the chain
    }

    // If key is not found, create a new entry and add it to the front of the list
    struct HashTableEntry *new_entry = malloc(sizeof(struct HashTableEntry));
    if (new_entry == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        return;
    }
    memcpy(new_entry->public_key, public_key, 32);  // Store the public key
    memcpy(new_entry->last_transaction_index, last_transaction_index, 8);  // Store the transaction index
    new_entry->next = table->entries[index];  // Insert new entry at the head of the list
    table->entries[index] = new_entry;  // Update the bucket to point to the new entry
}

// Function to free the memory used by the hash table
void free_hash_table(struct HashTable *table) {
    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        struct HashTableEntry *entry = table->entries[i];
        while (entry != NULL) {
            struct HashTableEntry *next_entry = entry->next;
            free(entry);  // Free each entry in the chain
            entry = next_entry;
        }
    }
}

uint64_t bytes_to_uint64(const unsigned char *bytes) {
    uint64_t result = 0;
    for (int i = 0; i < 8; i++) {
        result = (result << 8) | bytes[i];
    }
    return result;
}

void uint64_to_bytes(unsigned char *bytes, uint64_t value) {
    for (int i = 7; i >= 0; i--) {
        bytes[i] = value & 0xFF;  // Extract the lowest 8 bits
        value >>= 8;               // Shift right by 8 bits to move to the next byte
    }
}

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

int file_exists(const char *filename) {
    struct stat buffer;
    return (stat(filename, &buffer) == 0);
}

int load_public_key(unsigned char *public_key, const char *filename) {
    FILE *file = fopen(filename, "rb");
    if (file == NULL) {
        perror("Failed to open file for reading");
        return -1;
    }

    // Read the 32-byte public key
    if (fread(public_key, 1, crypto_sign_PUBLICKEYBYTES, file) != crypto_sign_PUBLICKEYBYTES) {
        perror("Failed to read public key from file");
        fclose(file);
        return -1;
    }

    fclose(file);
    return 0; // Success
}

int validate_and_add_transaction(struct Transaction *transaction,
                                 struct HashTable *user_cache,
                                 struct TransactionsCache *transactions_cache,
                                 const unsigned char *bank_public_key) {
    // Step 1: Check if sender has enough balance
    unsigned char *last_sender_transaction_index = lookup(user_cache, transaction->sender_public_key);
    uint64_t last_sender_balance = 0;
    uint64_t transfer_value = bytes_to_uint64(transaction->value_transferred);
    if (last_sender_transaction_index != NULL) {
        uint64_t sender_index = bytes_to_uint64(last_sender_transaction_index);
        const struct Transaction *last_sender_transaction = (sender_index < transactions_cache->count) ?
                                                            &transactions_cache->transactions[sender_index] : NULL;
        last_sender_balance = last_sender_transaction ? bytes_to_uint64(last_sender_transaction->new_sender_balance) : 0;
    }

    if ((last_sender_transaction_index == NULL || last_sender_balance == 0) && memcmp(transaction->sender_public_key, bank_public_key, 32) == 0) {
        last_sender_balance = transfer_value;
    }

    if (last_sender_balance < transfer_value) {
        fprintf(stderr, "Validation failed: Sender's balance is too low for the transfer\n");
        return -1; // Validation failed
    }

    // Step 2: Verify the hash
    unsigned char computed_hash[32];
    unsigned char concatenation_buffer[32 + 32 + 8 + 16]; // Buffer for concatenating sender, recipient, value, and nonce
    memcpy(concatenation_buffer, transaction->sender_public_key, 32);
    memcpy(concatenation_buffer + 32, transaction->recipient_public_key, 32);
    memcpy(concatenation_buffer + 64, transaction->value_transferred, 8);
    memcpy(concatenation_buffer + 72, transaction->nonce, 16);

    if (compute_sha256_hash(computed_hash, concatenation_buffer, sizeof(concatenation_buffer)) != 0) {
        fprintf(stderr, "Validation failed: Error computing transaction hash\n");
        return -1; // Validation failed
    }

    if (memcmp(computed_hash, transaction->hash, 32) != 0) {
        fprintf(stderr, "Validation failed: Computed hash does not match the provided hash\n");
        return -1; // Validation failed
    }

    // Step 3: Verify the digital signature
    if (verify_signature(transaction->digital_signature, transaction->hash, 32, transaction->sender_public_key) != 0) {
        fprintf(stderr, "Validation failed: Invalid digital signature\n");
        return -1; // Validation failed
    }

    // Step 4: Fill in the remaining fields for the transaction

    // Set the last transaction index for the sender
    if (last_sender_transaction_index != NULL) {
        memcpy(transaction->last_sender_transaction_index, last_sender_transaction_index, 8);
    } else {
        // If this is the first sender transaction (i.e., from the bank), set the index to 0
        assert(memcmp(transaction->sender_public_key, bank_public_key, 32) == 0);
        memset(transaction->last_sender_transaction_index, 0, 8);
    }

    // Set the last transaction index for the recipient
    unsigned char *last_recipient_transaction_index = lookup(user_cache, transaction->recipient_public_key);
    if (last_recipient_transaction_index != NULL) {
        memcpy(transaction->last_recipient_transaction_index, last_recipient_transaction_index, 8);
    } else {
        // If this is the first recipient transaction, set the index to 0
        memset(transaction->last_recipient_transaction_index, 0, 8);
    }

    // Update the sender's new balance
    uint64_t new_sender_balance = last_sender_balance - transfer_value;
    uint64_to_bytes(transaction->new_sender_balance, new_sender_balance);

    // Update the recipient's new balance
    if (last_recipient_transaction_index != NULL) {
        uint64_t recipient_index = bytes_to_uint64(last_recipient_transaction_index);
        const struct Transaction *last_recipient_transaction = (recipient_index < transactions_cache->count) ?
                                                               &transactions_cache->transactions[recipient_index] : NULL;
        uint64_t last_recipient_balance = last_recipient_transaction ? bytes_to_uint64(last_recipient_transaction->new_recipient_balance) : 0;
        uint64_t new_recipient_balance = last_recipient_balance + transfer_value;
        uint64_to_bytes(transaction->new_recipient_balance, new_recipient_balance);
    } else {
        uint64_to_bytes(transaction->new_recipient_balance, transfer_value);
    }

    // Assign the transaction index
    uint64_t new_transaction_index = transactions_cache->count;
    uint64_to_bytes(transaction->index, new_transaction_index);

    // Step 5: Add the transaction to the transaction cache
    if (add_transaction_to_cache(transactions_cache, transaction) != 0) {
        fprintf(stderr, "Error: Unable to add transaction to cache\n");
        return -1; // Failed to add transaction
    }

    // Step 6: Update the user cache with the new transaction index
    update(user_cache, transaction->sender_public_key, transaction->index);
    update(user_cache, transaction->recipient_public_key, transaction->index);

    return 0; // Success
}


int bytes_to_hex_string(char* buffer, size_t buffer_size, const unsigned char* bytes, int num_bytes) {
    int offset = 0;

    for (size_t i = 0; i < num_bytes; i++) {
        offset += snprintf(buffer + offset, buffer_size - offset, "%02X", bytes[i]);
    }

    return offset;
}

int hex_to_bytes(const char *hex_str, unsigned char *byte_array, size_t byte_array_size) {
    for (size_t i = 0; i < byte_array_size; i++) {
        // sscanf should return 1, indicating one successful assignment
        if (sscanf(hex_str + 2 * i, "%2hhx", &byte_array[i]) != 1) {
            return -1; // Error: Invalid hex string format
        }
    }
    return 0; // Success
}

int transaction_to_hex_string(char* buffer, size_t buffer_size, const struct Transaction* transaction) {
    int offset = 0;

    offset += snprintf(buffer + offset, buffer_size - offset, "Sender Public Key: 0X");
    offset += bytes_to_hex_string(buffer + offset, buffer_size - offset, transaction->sender_public_key, 32);
    offset += snprintf(buffer + offset, buffer_size - offset, "\n");

    offset += snprintf(buffer + offset, buffer_size - offset, "Recipient Public Key: 0X");
    offset += bytes_to_hex_string(buffer + offset, buffer_size - offset, transaction->recipient_public_key, 32);
    offset += snprintf(buffer + offset, buffer_size - offset, "\n");

    offset += snprintf(buffer + offset, buffer_size - offset, "Value transferred: 0X");
    offset += bytes_to_hex_string(buffer + offset, buffer_size - offset, transaction->value_transferred, 8);
    offset += snprintf(buffer + offset, buffer_size - offset, "\n");

    offset += snprintf(buffer + offset, buffer_size - offset, "Nonce: 0X");
    offset += bytes_to_hex_string(buffer + offset, buffer_size - offset, transaction->nonce, 16);
    offset += snprintf(buffer + offset, buffer_size - offset, "\n");

    offset += snprintf(buffer + offset, buffer_size - offset, "Hash: 0X");
    offset += bytes_to_hex_string(buffer + offset, buffer_size - offset, transaction->hash, 32);
    offset += snprintf(buffer + offset, buffer_size - offset, "\n");

    offset += snprintf(buffer + offset, buffer_size - offset, "Digital Signature: 0X");
    offset += bytes_to_hex_string(buffer + offset, buffer_size - offset, transaction->digital_signature, 64);
    offset += snprintf(buffer + offset, buffer_size - offset, "\n");

    offset += snprintf(buffer + offset, buffer_size - offset, "Last Sender Transaction Index: 0X");
    offset += bytes_to_hex_string(buffer + offset, buffer_size - offset, transaction->last_sender_transaction_index, 8);
    offset += snprintf(buffer + offset, buffer_size - offset, "\n");

    offset += snprintf(buffer + offset, buffer_size - offset, "Last Recipient Transaction Index: 0X");
    offset += bytes_to_hex_string(buffer + offset, buffer_size - offset, transaction->last_recipient_transaction_index, 8);
    offset += snprintf(buffer + offset, buffer_size - offset, "\n");

    offset += snprintf(buffer + offset, buffer_size - offset, "New Sender Balance: 0X");
    offset += bytes_to_hex_string(buffer + offset, buffer_size - offset, transaction->new_sender_balance, 8);
    offset += snprintf(buffer + offset, buffer_size - offset, "\n");

    offset += snprintf(buffer + offset, buffer_size - offset, "New Recipient Balance: 0X");
    offset += bytes_to_hex_string(buffer + offset, buffer_size - offset, transaction->new_recipient_balance, 8);
    offset += snprintf(buffer + offset, buffer_size - offset, "\n");

    offset += snprintf(buffer + offset, buffer_size - offset, "Transaction Index: 0X");
    offset += bytes_to_hex_string(buffer + offset, buffer_size - offset, transaction->index, 8);
    offset += snprintf(buffer + offset, buffer_size - offset, "\n");

    return offset; // Return the new offset
}

int transactions_cache_to_string(char* buffer, size_t buffer_size, const struct TransactionsCache* cache) {
    int offset = 0;
    int num_transactions_to_show = cache->count < NUM_TRANSACTIONS_TO_SHOW ? cache->count : NUM_TRANSACTIONS_TO_SHOW;

    for (int i = 0; i < num_transactions_to_show; i++) {
        int transaction_index = cache->count - num_transactions_to_show + i;

        offset += transaction_to_hex_string(buffer + offset, buffer_size - offset, &cache->transactions[transaction_index]);

        if (i < num_transactions_to_show - 1) {
            offset += snprintf(buffer + offset, buffer_size - offset, "\n");
        }
    }

    return offset;
}

int extract_param(const char *query, const char *param_name, unsigned char *dest, size_t size) {
    const char *pos = strstr(query, param_name);
    if (!pos || strncmp(pos + strlen(param_name), "0X", 2) != 0) {
        return -1; // Error: Key not found or missing "0X" prefix
    }

    if (hex_to_bytes(pos + strlen(param_name) + 2, dest, size) != 0) {
        return -2; // Error: Invalid hex string
    }

    return 0; // Success
}

int parse_query(const char *query, struct Transaction *tx) {
    int result;

    result = extract_param(query, "sender_public_key=", tx->sender_public_key, 32);
    if (result != 0) {
        return result;
    }

    result = extract_param(query, "recipient_public_key=", tx->recipient_public_key, 32);
    if (result != 0) {
        return result;
    }

    result = extract_param(query, "value_transferred=", tx->value_transferred, 8);
    if (result != 0) {
        return result;
    }

    result = extract_param(query, "nonce=", tx->nonce, 16);
    if (result != 0) {
        return result;
    }

    result = extract_param(query, "hash=", tx->hash, 32);
    if (result != 0) {
        return result;
    }

    result = extract_param(query, "digital_signature=", tx->digital_signature, 64);
    if (result != 0) {
        return result;
    }

    return 0; // Success
}

int main() {
    // Load/generate bank's public key
    unsigned char bank_public_key[crypto_sign_PUBLICKEYBYTES];

    if (!file_exists("public_key.bin")) {
        fprintf(stderr, "Bank's public key does not exist (run ./client to generate keys)\n");
        return 1;
    }

    if (load_public_key(bank_public_key, "public_key.bin") != 0) {
        fprintf(stderr, "Failed to load bank's public key\n");
        return 1;
    }

    struct TransactionsCache transactions_cache = {{0}, 0};

    // Will hold a user public key -> most recent transaction map
    struct HashTable user_cache;
    init_hash_table(&user_cache);

    int server_fd, new_socket;
    struct sockaddr_in6 address;  // Use sockaddr_in6 for IPv6
    int addrlen = sizeof(address);

    // Create socket file descriptor for IPv6
    if ((server_fd = socket(AF_INET6, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // Define the address and port (IPv6)
    address.sin6_family = AF_INET6;
    address.sin6_addr = in6addr_any;   // Bind to any IPv6 address
    address.sin6_port = htons(PORT);

    // Bind the socket to the network address and port
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    // Listen for incoming connections (up to 3 clients in the queue)
    if (listen(server_fd, 3) < 0) {
        perror("listen failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    printf("Server is listening on port %d\n", PORT);

    // Continuously accept and handle client connections
    while (1) {
        // Accept a connection (blocking call)
        if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
            perror("accept failed");
            close(server_fd);
            exit(EXIT_FAILURE);
        }

        // Read the client request into the buffer
        char request_buffer[REQUEST_BUFFER_SIZE] = {0};
        int bytes_read = read(new_socket, request_buffer, REQUEST_BUFFER_SIZE - 1);
        if (bytes_read > 0) {
            request_buffer[bytes_read] = '\0';  // Null-terminate the buffer
        }

        // Parse the query string into a Transaction struct
        char *query_start = strchr(request_buffer, '?');
        if (query_start) {
            query_start++;  // Move past the '?' character

            struct Transaction new_transaction = {0};  // Initialize all fields to zero
            int result = parse_query(query_start, &new_transaction);
            if (result == -1) {
                printf("Error: Missing or incorrectly formatted parameter.\n");
            } else if (result == -2) {
                printf("Error: Invalid hex string.\n");
            } else {
                printf("Transaction parsed successfully.\n");
                if (validate_and_add_transaction(&new_transaction, &user_cache, &transactions_cache, bank_public_key) == 0) {
                    printf("Transaction successfully validated and added to cache.\n");
                } else {
                    printf("Error: Transaction validation or addition failed.\n");
                }
            }
        }

        // Create the full HTTP response, including headers and body
        char http_response[RESPONSE_BUFFER_SIZE];
        char transactions_string[RESPONSE_BUFFER_SIZE] = {0};
        transactions_cache_to_string(transactions_string, sizeof(transactions_string), &transactions_cache);
        snprintf(http_response, sizeof(http_response),
                 "HTTP/1.1 200 OK\r\n"
                 "Content-Type: text/plain\r\n"
                 "Content-Length: %lu\r\n"
                 "\r\n"
                 "%s", strlen(transactions_string), transactions_string);

        // Send the HTTP response to the connected client
        send(new_socket, http_response, strlen(http_response), 0);

        // Close the client socket
        close(new_socket);
    }

    // Clean up (unreachable in this case, but good practice)
    close(server_fd);

    free_hash_table(&user_cache);

    return 0;
}
