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

struct Transaction {
    unsigned char index[16];                            // Transaction index (16 bytes)
    unsigned char sender_public_key[65];                // Sender public key (65 bytes)
    unsigned char recipient_public_key[65];             // Recipient public key (65 bytes)
    unsigned char last_sender_transaction_index[16];    // Last sender transaction hash (16 bytes)
    unsigned char last_recipient_transaction_index[16]; // Last recipient transaction hash (16 bytes)
    unsigned char new_sender_balance[8];                // New sender balance (8 bytes)
    unsigned char new_recipient_balance[8];             // New recipient balance (8 bytes)
    unsigned char hash[32];                             // Transaction hash (32 bytes)
    unsigned char digital_signature[72];                // Digital signature (72 bytes)
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

int validate_transaction(const struct Transaction* transaction) {
    // For now, just return 1 to indicate the transaction is valid
    return 1;  // 1 represents true (valid)
}

int bytes_to_hex_string(char* buffer, size_t buffer_size, const unsigned char* bytes, int num_bytes) {
    int offset = 0;

    for (size_t i = 0; i < num_bytes; i++) {
        offset += snprintf(buffer + offset, buffer_size - offset, "%02X", bytes[i]);
    }

    return offset;
}

int transaction_to_hex_string(char* buffer, size_t buffer_size, const struct Transaction* transaction) {
    int offset = 0;

    offset += snprintf(buffer + offset, buffer_size - offset, "Transaction Index: 0X");
    offset += bytes_to_hex_string(buffer + offset, buffer_size - offset, transaction->index, 16);
    offset += snprintf(buffer + offset, buffer_size - offset, "\n");

    offset += snprintf(buffer + offset, buffer_size - offset, "Sender Public Key: 0X");
    offset += bytes_to_hex_string(buffer + offset, buffer_size - offset, transaction->sender_public_key, 65);
    offset += snprintf(buffer + offset, buffer_size - offset, "\n");

    offset += snprintf(buffer + offset, buffer_size - offset, "Recipient Public Key: 0X");
    offset += bytes_to_hex_string(buffer + offset, buffer_size - offset, transaction->recipient_public_key, 65);
    offset += snprintf(buffer + offset, buffer_size - offset, "\n");

    offset += snprintf(buffer + offset, buffer_size - offset, "Last Sender Transaction Index: 0X");
    offset += bytes_to_hex_string(buffer + offset, buffer_size - offset, transaction->last_sender_transaction_index, 16);
    offset += snprintf(buffer + offset, buffer_size - offset, "\n");

    offset += snprintf(buffer + offset, buffer_size - offset, "Last Recipient Transaction Index: 0X");
    offset += bytes_to_hex_string(buffer + offset, buffer_size - offset, transaction->last_recipient_transaction_index, 16);
    offset += snprintf(buffer + offset, buffer_size - offset, "\n");

    offset += snprintf(buffer + offset, buffer_size - offset, "New Sender Balance: 0X");
    offset += bytes_to_hex_string(buffer + offset, buffer_size - offset, transaction->new_sender_balance, 8);
    offset += snprintf(buffer + offset, buffer_size - offset, "\n");

    offset += snprintf(buffer + offset, buffer_size - offset, "New Recipient Balance: 0X");
    offset += bytes_to_hex_string(buffer + offset, buffer_size - offset, transaction->new_recipient_balance, 8);
    offset += snprintf(buffer + offset, buffer_size - offset, "\n");

    offset += snprintf(buffer + offset, buffer_size - offset, "Transaction hash: 0X");
    offset += bytes_to_hex_string(buffer + offset, buffer_size - offset, transaction->hash, 32);
    offset += snprintf(buffer + offset, buffer_size - offset, "\n");

    offset += snprintf(buffer + offset, buffer_size - offset, "Digital Signature: 0X");
    offset += bytes_to_hex_string(buffer + offset, buffer_size - offset, transaction->digital_signature, 72);
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

int hex_to_bytes(const char *hex_str, unsigned char *byte_array, size_t byte_array_size) {
    for (size_t i = 0; i < byte_array_size; i++) {
        // sscanf should return 1, indicating one successful assignment
        if (sscanf(hex_str + 2 * i, "%2hhx", &byte_array[i]) != 1) {
            return -1; // Error: Invalid hex string format
        }
    }
    return 0; // Success
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

    result = extract_param(query, "index=", tx->index, 16);
    if (result != 0) {
        return result;
    }

    result = extract_param(query, "sender_public_key=", tx->sender_public_key, 65);
    if (result != 0) {
        return result;
    }

    result = extract_param(query, "recipient_public_key=", tx->recipient_public_key, 65);
    if (result != 0) {
        return result;
    }

    result = extract_param(query, "last_sender_transaction_index=", tx->last_sender_transaction_index, 16);
    if (result != 0) {
        return result;
    }

    result = extract_param(query, "last_recipient_transaction_index=", tx->last_recipient_transaction_index, 16);
    if (result != 0) {
        return result;
    }

    result = extract_param(query, "new_sender_balance=", tx->new_sender_balance, 8);
    if (result != 0) {
        return result;
    }

    result = extract_param(query, "new_recipient_balance=", tx->new_recipient_balance, 8);
    if (result != 0) {
        return result;
    }

    result = extract_param(query, "hash=", tx->hash, 32);
    if (result != 0) {
        return result;
    }

    result = extract_param(query, "digital_signature=", tx->digital_signature, 72);
    if (result != 0) {
        return result;
    }

    return 0; // Success
}

int main() {
    struct TransactionsCache transactions_cache = {{0}, 0};

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
                if (validate_transaction(&new_transaction)) {
                    if (add_transaction_to_cache(&transactions_cache, &new_transaction) == 0) {
                        printf("Transaction added to cache.\n");
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

    return 0;
}
