#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define PORT 8080
#define BUFFER_SIZE 1024
#define PUBLIC_KEY_SIZE 65
#define NUM_TRANSACTIONS_TO_SHOW 10

struct Transaction {
    unsigned char sender_public_key[65];               // Sender public key (65 bytes)
    unsigned char recipient_public_key[65];            // Recipient public key (65 bytes)
    unsigned char last_sender_transaction_hash[32];    // Last sender transaction hash (32 bytes)
    unsigned char last_recipient_transaction_hash[32]; // Last recipient transaction hash (32 bytes)
    unsigned char new_sender_balance[8];               // New sender balance (8 bytes)
    unsigned char new_recipient_balance[8];            // New recipient balance (8 bytes)
    unsigned char digital_signature[72];               // Digital signature (72 bytes)
};

int bytes_to_hex_string(char* buffer, size_t buffer_size, const unsigned char* bytes, int num_bytes) {
    int offset = 0;

    for (size_t i = 0; i < num_bytes; i++) {
        offset += snprintf(buffer + offset, buffer_size - offset, "%02X", bytes[i]);
    }

    return offset;
}

// Convert a Transaction struct to a hex string and return the new offset
int transaction_to_hex_string(char* buffer, size_t buffer_size, const struct Transaction* transaction) {
    int offset = 0;

    offset += snprintf(buffer + offset, buffer_size - offset, "Sender Public Key: 0X");
    offset += bytes_to_hex_string(buffer + offset, buffer_size - offset, transaction->sender_public_key, 65);
    offset += snprintf(buffer + offset, buffer_size - offset, "\n");

    offset += snprintf(buffer + offset, buffer_size - offset, "Recipient Public Key: 0X");
    offset += bytes_to_hex_string(buffer + offset, buffer_size - offset, transaction->recipient_public_key, 65);
    offset += snprintf(buffer + offset, buffer_size - offset, "\n");

    offset += snprintf(buffer + offset, buffer_size - offset, "Last Sender Transaction Hash: 0X");
    offset += bytes_to_hex_string(buffer + offset, buffer_size - offset, transaction->last_sender_transaction_hash, 32);
    offset += snprintf(buffer + offset, buffer_size - offset, "\n");

    offset += snprintf(buffer + offset, buffer_size - offset, "Last Recipient Transaction Hash: 0X");
    offset += bytes_to_hex_string(buffer + offset, buffer_size - offset, transaction->last_recipient_transaction_hash, 32);
    offset += snprintf(buffer + offset, buffer_size - offset, "\n");

    offset += snprintf(buffer + offset, buffer_size - offset, "New Sender Balance: 0X");
    offset += bytes_to_hex_string(buffer + offset, buffer_size - offset, transaction->new_sender_balance, 8);
    offset += snprintf(buffer + offset, buffer_size - offset, "\n");

    offset += snprintf(buffer + offset, buffer_size - offset, "New Recipient Balance: 0X");
    offset += bytes_to_hex_string(buffer + offset, buffer_size - offset, transaction->new_recipient_balance, 8);
    offset += snprintf(buffer + offset, buffer_size - offset, "\n");

    offset += snprintf(buffer + offset, buffer_size - offset, "Digital Signature: 0X");
    offset += bytes_to_hex_string(buffer + offset, buffer_size - offset, transaction->digital_signature, 72);
    offset += snprintf(buffer + offset, buffer_size - offset, "\n");

    return offset; // Return the new offset
}

// Function that takes an array of transactions and fills the buffer
int transactions_to_string(char* buffer, size_t buffer_size, const struct Transaction* transactions, int num_transactions) {
    int offset = 0;

    for (int i = 0; i < num_transactions; i++) {
        offset += snprintf(buffer + offset, buffer_size - offset, "Transaction index: %d\n", i);
        offset += transaction_to_hex_string(buffer + offset, buffer_size - offset, &transactions[i]);
        if (i < num_transactions - 1) {
            offset += snprintf(buffer + offset, buffer_size - offset, "\n");
        }
    }

    return offset;
}

int main() {
    // Initialize an array of transactions
    struct Transaction transaction = {
        {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40, 0x41},
        {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40, 0x41},
        {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99},
        {0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA},
        {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
        {0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01},
        {0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD}
    };
    struct Transaction transactions[NUM_TRANSACTIONS_TO_SHOW];
    for (int i = 0; i < NUM_TRANSACTIONS_TO_SHOW; i++) {
        transactions[i] = transaction;
    }

    int server_fd, new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    char buffer[BUFFER_SIZE] = {0};
    int request_counter = 0;

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

        // Read the client request into the buffer (optional, just for printing)
        char request_buffer[BUFFER_SIZE] = {0};
        int bytes_read = read(new_socket, request_buffer, BUFFER_SIZE - 1);
        if (bytes_read > 0) {
            request_buffer[bytes_read] = '\0';  // Null-terminate the buffer
            printf("Received request:\n%s\n", request_buffer);
        }

        // Extract the hash values from the query string
        char *hash1 = NULL;
        char *hash2 = NULL;
        char *query_start = strchr(request_buffer, '?');
        if (query_start) {
            query_start++;  // Move past the '?' character

            char *hash1_start = strstr(query_start, "hash1=");
            char *hash2_start = strstr(query_start, "hash2=");

            // Extract hash1
            if (hash1_start) {
                hash1_start += 6;  // Move past "hash1="
                char *hash1_end = strchr(hash1_start, '&');
                if (!hash1_end) {
                    hash1_end = strchr(hash1_start, ' ');
                }
                if (hash1_end) {
                    *hash1_end = '\0';  // Null-terminate the hash1 string
                }
                hash1 = hash1_start;
            }

            // Extract hash2
            if (hash2_start) {
                hash2_start += 6;  // Move past "hash2="
                char *hash2_end = strchr(hash2_start, ' ');
                if (hash2_end) {
                    *hash2_end = '\0';  // Null-terminate the hash2 string
                }
                hash2 = hash2_start;
            }
        }

        if (hash1) {
            printf("Received hash1: %s\n", hash1);
        }

        if (hash2) {
            printf("Received hash2: %s\n", hash2);
        }

        char transactions_string[NUM_TRANSACTIONS_TO_SHOW * BUFFER_SIZE];
        memset(transactions_string, 0, NUM_TRANSACTIONS_TO_SHOW * BUFFER_SIZE);
        transactions_to_string(transactions_string, sizeof(transactions_string), transactions, NUM_TRANSACTIONS_TO_SHOW);

        // Create the full HTTP response, including headers and body
        char http_response[(NUM_TRANSACTIONS_TO_SHOW + 1) * BUFFER_SIZE];
        snprintf(http_response, sizeof(http_response),
                 "HTTP/1.1 200 OK\r\n"
                 "Content-Type: text/plain\r\n"
                 "Content-Length: %lu\r\n"
                 "\r\n"
                 "%s", strlen(transactions_string), transactions_string);

        // Send the HTTP response to the connected client
        send(new_socket, http_response, strlen(http_response), 0);
        printf("HTTP response sent to client: %d\n", request_counter);

        request_counter += 1;

        // Close the client socket
        close(new_socket);
    }

    // Clean up (unreachable in this case, but good practice)
    close(server_fd);

    return 0;
}
