#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sodium.h>
#include "common.h"

#define HEX_PREFIX_LEN 2  // Length of "0X"
#define SENDER_PUBLIC_KEY_LEN 66  // 32 bytes -> 64 hex chars + "0X" -> 66
#define RECIPIENT_PUBLIC_KEY_LEN 66  // 32 bytes -> 64 hex chars + "0X" -> 66
#define TX_INDEX_LEN 18  // 8 bytes -> 16 hex chars + "0X" -> 18
#define BALANCE_LEN 18   // 8 bytes -> 16 hex chars + "0X" -> 18
#define HASH_LEN 66  // 32 bytes -> 64 hex chars + "0X" -> 66
#define SIGNATURE_LEN 130  // 64 bytes -> 128 hex chars + "0X" -> 130

#define SERVER_ADDR "127.0.0.1"
#define SERVER_PORT 8080

int validate_hex_string(const char *hex_string, int expected_len) {
    return strlen(hex_string) == expected_len && strncmp(hex_string, "0X", HEX_PREFIX_LEN) == 0;
}

int main(int argc, char *argv[]) {
    if (argc != 7) {
        fprintf(stderr, "Usage: %s <sender_public_key> <recipient_public_key> <last_sender_transaction_index> <last_recipient_transaction_index> <new_sender_balance> <new_recipient_balance>\n", argv[0]);
        return 1;
    }

    const char *sender_public_key = argv[1];
    const char *recipient_public_key = argv[2];
    const char *last_sender_transaction_index = argv[3];
    const char *last_recipient_transaction_index = argv[4];
    const char *new_sender_balance = argv[5];
    const char *new_recipient_balance = argv[6];

    // Validate lengths of provided hex strings
    if (!validate_hex_string(sender_public_key, SENDER_PUBLIC_KEY_LEN)) {
        fprintf(stderr, "Error: Invalid sender public key length.\n");
        return 1;
    }
    if (!validate_hex_string(recipient_public_key, RECIPIENT_PUBLIC_KEY_LEN)) {
        fprintf(stderr, "Error: Invalid recipient public key length.\n");
        return 1;
    }
    if (!validate_hex_string(last_sender_transaction_index, TX_INDEX_LEN)) {
        fprintf(stderr, "Error: Invalid last sender transaction index length.\n");
        return 1;
    }
    if (!validate_hex_string(last_recipient_transaction_index, TX_INDEX_LEN)) {
        fprintf(stderr, "Error: Invalid last recipient transaction index length.\n");
        return 1;
    }
    if (!validate_hex_string(new_sender_balance, BALANCE_LEN)) {
        fprintf(stderr, "Error: Invalid new sender balance length.\n");
        return 1;
    }
    if (!validate_hex_string(new_recipient_balance, BALANCE_LEN)) {
        fprintf(stderr, "Error: Invalid new recipient balance length.\n");
        return 1;
    }

    // Hardcoded values
    const char *index = "0X1234567890ABCDEF";
    const char *digital_signature = "0X1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF";

    unsigned char hash[crypto_hash_sha256_BYTES];
    unsigned char public_key[crypto_sign_PUBLICKEYBYTES];
    unsigned char private_key[crypto_sign_SECRETKEYBYTES];
    unsigned char signature[crypto_sign_BYTES];


    struct Transaction tx = {0};

    if (hex_to_bytes(sender_public_key, tx.sender_public_key, 32) != 0) {
        fprintf(stderr, "Error decoding sender public key\n");
        return 1;
    }

    if (hex_to_bytes(recipient_public_key, tx.recipient_public_key, 32) != 0) {
        fprintf(stderr, "Error decoding recipient public key\n");
        return 1;
    }

    if (hex_to_bytes(last_sender_transaction_index, tx.last_sender_transaction_index, 8) != 0) {
        fprintf(stderr, "Error decoding last sender transaction index\n");
        return 1;
    }

    if (hex_to_bytes(last_recipient_transaction_index, tx.last_recipient_transaction_index, 8) != 0) {
        fprintf(stderr, "Error decoding last recipient transaction index\n");
        return 1;
    }

    if (hex_to_bytes(new_sender_balance, tx.new_sender_balance, 8) != 0) {
        fprintf(stderr, "Error decoding new sender balance\n");
        return 1;
    }

    if (hex_to_bytes(new_recipient_balance, tx.new_recipient_balance, 8) != 0) {
        fprintf(stderr, "Error decoding new recipient balance\n");
        return 1;
    }

    if (hash_transaction(hash, &tx) != 0) {
        fprintf(stderr, "Error computing transaction hash\n");
        return 1;
    }

    char hash_str[2 * crypto_hash_sha256_BYTES + 3]; // 64 hex chars + 2 for "0X" + 1 for null terminator
    snprintf(hash_str, sizeof(hash_str), "0X");
    if (bytes_to_hex_string(hash_str + 2, sizeof(hash_str) - 2, hash, sizeof(hash)) < 0) {
        fprintf(stderr, "Error converting hash to hex string\n");
        return 1;
    }


    // Generate key pair
    if (generate_key_pair(public_key, private_key) != 0) {
        fprintf(stderr, "Failed to generate key pair\n");
        return 1;
    }

    // Sign the message
    unsigned char message[32] = {0};
    if (sign_message(message, 32, private_key, signature) != 0) {
        fprintf(stderr, "Failed to sign message\n");
        return 1;
    }

    // Create the full URL
    char request_url[1024];
    snprintf(request_url, sizeof(request_url),
             "http://localhost:8080/?index=%s&sender_public_key=%s&recipient_public_key=%s"
             "&last_sender_transaction_index=%s&last_recipient_transaction_index=%s"
             "&new_sender_balance=%s&new_recipient_balance=%s&hash=%s&digital_signature=%s",
             index, sender_public_key, recipient_public_key, last_sender_transaction_index,
             last_recipient_transaction_index, new_sender_balance, new_recipient_balance,
             hash_str, digital_signature);

    // Socket setup
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Socket creation failed");
        return 1;
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);

    if (inet_pton(AF_INET, SERVER_ADDR, &server_addr.sin_addr) <= 0) {
        perror("Invalid address");
        close(sock);
        return 1;
    }

    // Connect to the server
    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection failed");
        close(sock);
        return 1;
    }

    // Send the request
    if (send(sock, request_url, strlen(request_url), 0) < 0) {
        perror("Send failed");
        close(sock);
        return 1;
    }

    // Receive the response
    char response[4096];
    int bytes_received = recv(sock, response, sizeof(response) - 1, 0);
    if (bytes_received < 0) {
        perror("Receive failed");
    } else {
        response[bytes_received] = '\0';  // Null-terminate the response
        printf("Response from server:\n%s\n", response);
    }

    // Close the socket
    close(sock);

    return 0;
}

