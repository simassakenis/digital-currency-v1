#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>

#define PORT 8080
#define BUFFER_SIZE 1024

int request_counter = 0;
pthread_mutex_t counter_lock;

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

int main() {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    char buffer[BUFFER_SIZE] = {0};

    // Initialize the mutex for thread safety
    pthread_mutex_init(&counter_lock, NULL);

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

        // // Read the client request into the buffer (optional, just for printing)
        // int bytes_read = read(new_socket, buffer, BUFFER_SIZE - 1);
        // if (bytes_read > 0) {
        //     buffer[bytes_read] = '\0';  // Null-terminate the buffer
        //     printf("Received request:\n%s\n", buffer);
        // }

        // Lock the mutex before updating the counter
        pthread_mutex_lock(&counter_lock);
        int current_request_number = request_counter++;
        pthread_mutex_unlock(&counter_lock);

        // Create the response body with the request number
        char response_body[BUFFER_SIZE];
        // snprintf(response_body, sizeof(response_body), "Hello, World! This is request number %d.\n", current_request_number);

        int index = 0;
        int recipient_pk = 12;

        unsigned char sender_pk[5] = {0x12, 0xA5, 0x4B, 0xFF, 0x90};
        char sender_pk_hex[5 * 2 + 1];
        bytes_to_hex_string(sender_pk, 5, sender_pk_hex, sizeof(sender_pk_hex));

        snprintf(response_body, sizeof(response_body), "Index: %d\nSender public key (hex): %s\nRecipient public key: %d\n", index, sender_pk_hex, recipient_pk);

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
        printf("HTTP response sent to client: %d\n", current_request_number);

        // Close the client socket
        close(new_socket);
    }

    // Clean up the mutex (unreachable in this case, but good practice)
    pthread_mutex_destroy(&counter_lock);
    close(server_fd);

    return 0;
}
