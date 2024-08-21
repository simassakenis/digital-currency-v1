#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define PORT 8080
#define BUFFER_SIZE 1024
#define PUBLIC_KEY_SIZE 65

struct Transaction {
    unsigned char sender_public_key[65];               // Sender public key (65 bytes)
    unsigned char recipient_public_key[65];            // Recipient public key (65 bytes)
    unsigned char last_sender_transaction_hash[32];    // Last sender transaction hash (32 bytes)
    unsigned char last_recipient_transaction_hash[32]; // Last recipient transaction hash (32 bytes)
    unsigned char new_sender_balance[8];               // New sender balance (8 bytes)
    unsigned char new_recipient_balance[8];            // New recipient balance (8 bytes)
    unsigned char digital_signature[72];               // Digital signature (72 bytes)
};

void bytes_to_hex_string(const unsigned char* bytes, size_t len, char* hex_string, size_t hex_string_size) {
    // Check that the buffer is large enough
    if (hex_string_size < (len * 2 + 1)) {
        // Not enough space in the buffer, handle error as needed
        return;
    }

    // Convert each byte to a 2-digit hexadecimal representation
    for (size_t i = 0; i < len; i++) {
        // Use snprintf to safely format each byte as a hexadecimal string
        snprintf(hex_string + (i * 2), 3, "%02X", bytes[i]);
    }

    // Null-terminate the string
    hex_string[len * 2] = '\0';
}

void transaction_to_hex_string(const struct Transaction* transaction, char* output_buffer, size_t buffer_size) {
    char hex_string[145]; // Buffer for the hex string representation (2 * 72 + 1, the largest single field)
    size_t offset = 0;

    // Convert each field and append to the output buffer
    bytes_to_hex_string(transaction->sender_public_key, 65, hex_string, sizeof(hex_string));
    offset += snprintf(output_buffer + offset, buffer_size - offset, "Sender Public Key: %s\n", hex_string);

    bytes_to_hex_string(transaction->recipient_public_key, 65, hex_string, sizeof(hex_string));
    offset += snprintf(output_buffer + offset, buffer_size - offset, "Recipient Public Key: %s\n", hex_string);

    bytes_to_hex_string(transaction->last_sender_transaction_hash, 32, hex_string, sizeof(hex_string));
    offset += snprintf(output_buffer + offset, buffer_size - offset, "Last Sender Transaction Hash: %s\n", hex_string);

    bytes_to_hex_string(transaction->last_recipient_transaction_hash, 32, hex_string, sizeof(hex_string));
    offset += snprintf(output_buffer + offset, buffer_size - offset, "Last Recipient Transaction Hash: %s\n", hex_string);

    bytes_to_hex_string(transaction->new_sender_balance, 8, hex_string, sizeof(hex_string));
    offset += snprintf(output_buffer + offset, buffer_size - offset, "New Sender Balance: %s\n", hex_string);

    bytes_to_hex_string(transaction->new_recipient_balance, 8, hex_string, sizeof(hex_string));
    offset += snprintf(output_buffer + offset, buffer_size - offset, "New Recipient Balance: %s\n", hex_string);

    bytes_to_hex_string(transaction->digital_signature, 72, hex_string, sizeof(hex_string));
    snprintf(output_buffer + offset, buffer_size - offset, "Digital Signature: %s\n", hex_string);
}

int main() {
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

        // Create the response body with the request number
        char response_body[BUFFER_SIZE];
        // snprintf(response_body, sizeof(response_body), "Hello, World! This is request number %d.\n", current_request_number);

        int transaction_index = 0;

        struct Transaction transaction = {
            {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40, 0x41},
            {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40, 0x41},
            {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99},
            {0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA},
            {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
            {0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01},
            {0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD}
        };

        // Initialize an array of 10 transactions
        struct Transaction transactions[10];
        for (int i = 0; i < 10; ++i) {
            transactions[i] = transaction;
        }

        char transaction_string[BUFFER_SIZE];
        transaction_to_hex_string(&transaction, transaction_string, sizeof(transaction_string));

        snprintf(response_body, sizeof(response_body), "Index: %d\n%s", transaction_index, transaction_string);

        // Create the full HTTP response, including headers and body
        char http_response[BUFFER_SIZE];
        snprintf(http_response, sizeof(http_response),
                 "HTTP/1.1 200 OK\r\n"
                 "Content-Type: text/plain\r\n"
                 "Content-Length: %lu\r\n"
                 "\r\n"
                 "%s", strlen(response_body), response_body);

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
