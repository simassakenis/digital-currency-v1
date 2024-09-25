#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sodium.h>
#include <sys/stat.h>
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

int file_exists(const char *filename) {
    struct stat buffer;
    return (stat(filename, &buffer) == 0);
}

int validate_hex_string(const char *hex_string, int expected_len) {
    return strlen(hex_string) == expected_len && strncmp(hex_string, "0X", HEX_PREFIX_LEN) == 0;
}

int main(int argc, char *argv[]) {
    // No arguments: load or generate keys
    if (argc == 1) {
        unsigned char public_key[crypto_sign_PUBLICKEYBYTES];
        unsigned char private_key[crypto_sign_SECRETKEYBYTES]; // Full 64-byte buffer for private key

        // Check if the public and private key files already exist
        if (file_exists("public_key.bin") && file_exists("private_key.bin")) {
            printf("Keys already exist. Loading from files...\n");

            // Load the public key from file
            if (load_public_key(public_key, "public_key.bin") != 0) {
                fprintf(stderr, "Failed to load public key\n");
                return 1;
            }

            // Load the private key from file (this will regenerate the full 64-byte private key)
            if (load_private_key(private_key, public_key, "private_key.bin") != 0) {
                fprintf(stderr, "Failed to load private key\n");
                return 1;
            }

        } else {
            printf("Keys do not exist. Generating new keys...\n");

            // Generate new key pair
            if (generate_key_pair(public_key, private_key) != 0) {
                fprintf(stderr, "Failed to generate key pair\n");
                return 1;
            }

            // Save the public key to file
            if (save_public_key(public_key, "public_key.bin") != 0) {
                fprintf(stderr, "Failed to save public key\n");
                return 1;
            }

            // Save only the first 32 bytes of the private key to file
            if (save_private_key(private_key, "private_key.bin") != 0) {
                fprintf(stderr, "Failed to save private key\n");
                return 1;
            }
        }

        // Print the keys as hex strings
        char public_key_hex[crypto_sign_PUBLICKEYBYTES * 2 + 1]; // 2 hex digits per byte
        char private_key_hex[32 * 2 + 1]; // Only the first 32 bytes of private key

        // Convert keys to hex strings
        bytes_to_hex_string(public_key_hex, sizeof(public_key_hex), public_key, crypto_sign_PUBLICKEYBYTES);
        bytes_to_hex_string(private_key_hex, sizeof(private_key_hex), private_key, 32); // Only print 32 bytes

        // Print the keys
        printf("Public Key: 0X%s\n", public_key_hex);
        printf("Private Key: 0X%s\n", private_key_hex);

        return 0;
    }

    // Transaction mode (3 arguments)
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <recipient_public_key> <value_transferred> <nonce>\n", argv[0]);
        return 1;
    }

    const char *recipient_public_key = argv[1];
    const char *value_transferred = argv[2];
    const char *nonce = argv[3];

    // Validate lengths of provided hex strings
    if (!validate_hex_string(recipient_public_key, 66)) {
        fprintf(stderr, "Error: Invalid recipient public key length.\n");
        return 1;
    }

    if (!validate_hex_string(value_transferred, 18)) {
        fprintf(stderr, "Error: Invalid trasferred value length.\n");
        return 1;
    }

    if (!validate_hex_string(nonce, 34)) {
        fprintf(stderr, "Error: Invalid nonce length.\n");
        return 1;
    }

    unsigned char sender_public_key[crypto_sign_PUBLICKEYBYTES];
    unsigned char sender_private_key[crypto_sign_SECRETKEYBYTES];

    if (load_public_key(sender_public_key, "public_key.bin") != 0) {
        fprintf(stderr, "Failed to load public key (to generate public-private key pair run ./simple_client)\n");
        return 1;
    }

    if (load_private_key(sender_private_key, sender_public_key, "private_key.bin") != 0) {
        fprintf(stderr, "Failed to load private key (to generate public-private key pair run ./simple_client)\n");
        return 1;
    }

    // Compute the hash of concatenated public keys, value, and nonce
    unsigned char concatenated_data[32 + 32 + 8 + 16];
    int offset = 0;

    memcpy(concatenated_data, sender_public_key, 32);
    offset += 32;

    if (hex_to_bytes(recipient_public_key + 2, concatenated_data + offset, 32) != 0) {
        fprintf(stderr, "Error decoding recipient public key\n");
        return 1;
    }
    offset += 32;

    if (hex_to_bytes(value_transferred + 2, concatenated_data + offset, 8) != 0) {
        fprintf(stderr, "Error decoding value transferred\n");
        return 1;
    }
    offset += 8;

    if (hex_to_bytes(nonce + 2, concatenated_data + offset, 16) != 0) {
        fprintf(stderr, "Error decoding nonce\n");
        return 1;
    }
    offset += 16;

    unsigned char hash[crypto_hash_sha256_BYTES];
    if (compute_sha256_hash(hash, concatenated_data, sizeof(concatenated_data)) != 0) {
        fprintf(stderr, "Error computing hash\n");
        return 1;
    }

    char hash_str[2 * crypto_hash_sha256_BYTES + 1]; // 64 hex chars + 1 for null terminator
    if (bytes_to_hex_string(hash_str, sizeof(hash_str), hash, sizeof(hash)) < 0) {
        fprintf(stderr, "Error converting hash to hex string\n");
        return 1;
    }

    unsigned char signature[crypto_sign_BYTES];
    if (sign_message(hash, sizeof(hash), sender_private_key, signature) != 0) {
        fprintf(stderr, "Failed to sign message\n");
        return 1;
    }

    char signature_str[2 * crypto_sign_BYTES + 1]; // 128 hex chars + 1 for null terminator
    if (bytes_to_hex_string(signature_str, sizeof(signature_str), signature, sizeof(signature)) < 0) {
        fprintf(stderr, "Error converting hash to hex string\n");
        return 1;
    }

    char sender_public_key_str[2 * 32 + 1]; // 64 hex chars + 1 for null terminator
    if (bytes_to_hex_string(sender_public_key_str, sizeof(sender_public_key_str), sender_public_key, sizeof(sender_public_key)) < 0) {
        fprintf(stderr, "Error converting sender public key to hex string\n");
        return 1;
    }

    // Create the full URL
    char request_url[1024];
    snprintf(request_url, sizeof(request_url),
             "http://localhost:8080/?sender_public_key=0X%s&recipient_public_key=%s"
             "&value_transferred=%s&nonce=%s&hash=0X%s&digital_signature=0X%s",
             sender_public_key_str, recipient_public_key, value_transferred, nonce,
             hash_str, signature_str);

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

