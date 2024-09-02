#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define HEX_PREFIX_LEN 2  // Length of "0X"
#define SENDER_PUBLIC_KEY_LEN 132  // 65 bytes -> 130 hex chars + "0X" -> 132
#define RECIPIENT_PUBLIC_KEY_LEN 132
#define TX_INDEX_LEN 34  // 16 bytes -> 32 hex chars + "0X" -> 34
#define BALANCE_LEN 18   // 8 bytes -> 16 hex chars + "0X" -> 18
#define HASH_LEN 66  // 32 bytes -> 64 hex chars + "0X" -> 66
#define SIGNATURE_LEN 146  // 72 bytes -> 144 hex chars + "0X" -> 146

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
    const char *index = "0X1234567890ABCDEF1234567890ABCDEF";
    const char *hash = "0XDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF";
    const char *digital_signature = "0X1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCD";

    // Create the full URL
    char request_url[1024];
    snprintf(request_url, sizeof(request_url),
             "http://localhost:8080/?index=%s&sender_public_key=%s&recipient_public_key=%s"
             "&last_sender_transaction_index=%s&last_recipient_transaction_index=%s"
             "&new_sender_balance=%s&new_recipient_balance=%s&hash=%s&digital_signature=%s",
             index, sender_public_key, recipient_public_key, last_sender_transaction_index,
             last_recipient_transaction_index, new_sender_balance, new_recipient_balance,
             hash, digital_signature);

    printf("URL: %s\n", request_url);

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

