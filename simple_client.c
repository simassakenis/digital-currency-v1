#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sodium.h>

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

int compute_sha256_hash(unsigned char *output_buffer, const unsigned char *input_data, unsigned long long input_length) {
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
    const char *hash = "0XDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF";
    const char *digital_signature = "0X1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF";

    // unsigned char hash[SHA256_HASH_SIZE];
    unsigned char public_key[crypto_sign_PUBLICKEYBYTES];
    unsigned char private_key[crypto_sign_SECRETKEYBYTES];
    unsigned char signature[crypto_sign_BYTES];

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
             hash, digital_signature);

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

