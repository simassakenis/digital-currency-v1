#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define PORT 8080
#define REQUEST_BUFFER_SIZE 10240
#define RESPONSE_BUFFER_SIZE 10240
#define NUM_TRANSACTIONS_TO_SHOW 10
#define TRANSACTIONS_CACHE_SIZE 128
#define USER_CACHE_SIZE 128

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

struct HashTableEntry {
    unsigned char public_key[32];     // The 32-byte public key
    struct Transaction *transaction;  // Pointer to the most recent transaction
    struct HashTableEntry *next;      // For handling collisions (chaining)
};


struct HashTable {
    struct HashTableEntry *entries[USER_CACHE_SIZE];  // Array of pointers to entries (buckets)
};

unsigned int hash_table_index(const unsigned char *public_key) {
    unsigned int index = 0;
    for (int i = 0; i < 32; i++) {
        // Multiply by 31 (a prime) for better distribution of hash values
        index = (index * 31) + public_key[i];
    }
    return index % USER_CACHE_SIZE;
}

void insert_or_update(struct HashTable *table, const unsigned char *public_key, struct Transaction *transaction) {
    unsigned int index = hash_table_index(public_key);
    struct HashTableEntry *entry = table->entries[index];

    // Search for the public key in the chain
    while (entry != NULL) {
        if (memcmp(entry->public_key, public_key, 32) == 0) {
            entry->transaction = transaction;  // Update the transaction pointer
            return;
        }
        entry = entry->next;
    }

    // If not found, create a new entry
    struct HashTableEntry *new_entry = malloc(sizeof(struct HashTableEntry));
    memcpy(new_entry->public_key, public_key, 32);
    new_entry->transaction = transaction;
    new_entry->next = table->entries[index];
    table->entries[index] = new_entry;
}

struct Transaction *lookup(const struct HashTable *table, const unsigned char *public_key) {
    unsigned int index = hash_table_index(public_key);
    struct HashTableEntry *entry = table->entries[index];

    // Traverse the chain
    while (entry != NULL) {
        if (memcmp(entry->public_key, public_key, 32) == 0) {
            return entry->transaction;
        }
        entry = entry->next;
    }
    return NULL;  // Not found
}

void init_hash_table(struct HashTable *table) {
    for (int i = 0; i < USER_CACHE_SIZE; i++) {
        table->entries[i] = NULL;
    }
}

void free_hash_table(struct HashTable *table) {
    for (int i = 0; i < USER_CACHE_SIZE; i++) {
        struct HashTableEntry *entry = table->entries[i];
        while (entry != NULL) {
            struct HashTableEntry *next = entry->next;
            free(entry);
            entry = next;
        }
    }
}

int validate_transaction(const struct Transaction *transaction, const struct HashTable *user_cache) {
    struct Transaction *last_sender_transaction = lookup(user_cache, transaction->sender_public_key);
    struct Transaction *last_recipient_transaction = lookup(user_cache, transaction->recipient_public_key);
    return 1;  // 1 represents true (valid)
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

int main() {
    struct TransactionsCache transactions_cache = {{0}, 0};

    // Will hold a user public key -> most recent transaction map
    struct HashTable user_cache;
    init_hash_table(&user_cache);

    int server_fd, new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);

    // Create socket file descriptor
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // Define the address and port
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

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
                if (validate_transaction(&new_transaction, &user_cache)) {
                    if (add_transaction_to_cache(&transactions_cache, &new_transaction) == 0) {
                        printf("Transaction added to cache.\n");
                        struct Transaction *new_transaction_in_cache = &transactions_cache.transactions[transactions_cache.count - 1];
                        insert_or_update(&user_cache, new_transaction.sender_public_key, new_transaction_in_cache);
                        insert_or_update(&user_cache, new_transaction.recipient_public_key, new_transaction_in_cache);
                    } else {
                        printf("Error: Cache is full. Cannot add transaction.\n");
                    }
                } else {
                    printf("Error: Transaction is invalid. Cannot add to cache.\n");
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
