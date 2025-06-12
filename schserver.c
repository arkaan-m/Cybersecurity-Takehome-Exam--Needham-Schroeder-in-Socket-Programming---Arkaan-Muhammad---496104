// schserver.c - Needham-Schroeder server
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define SERVER_PORT 8000
#define BUFFER_SIZE 1024

const char *Kbs = "BSecretKey54321"; // shared with B
const char *Kas = "ASecretKey12345"; // shared with A

void xor_crypt(char *data, const char *key, size_t len, size_t key_len) {
    for (size_t i = 0; i < len; ++i) {
        data[i] ^= key[i % key_len];
    }
}

int main() {
    int server_fd, client_fd;
    struct sockaddr_in address;
    char buffer[BUFFER_SIZE];
    socklen_t addrlen = sizeof(address);

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("Socket failed");
        exit(EXIT_FAILURE);
    }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(SERVER_PORT);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }

    listen(server_fd, 3);
    printf("Server listening on port %d...\n", SERVER_PORT);

    while (1) {
        client_fd = accept(server_fd, (struct sockaddr *)&address, &addrlen);
        if (client_fd < 0) {
            perror("Accept failed");
            continue;
        }

        int n = recv(client_fd, buffer, BUFFER_SIZE - 1, 0);
        if (n <= 0) {
            close(client_fd);
            continue;
        }

        buffer[n] = '\0';
        printf("Received: %s\n", buffer);

        // Parse request: A|B|12345
        char requester[50], receiver[50], nonce[50];
        if (sscanf(buffer, "%49[^|]|%49[^|]|%49s", requester, receiver, nonce) != 3) {
            printf("Invalid format.\n");
            close(client_fd);
            continue;
        }

        const char *Ks = "SessionKeyABC";

        // Construct message1: nonce|B|Ks
        char message1[BUFFER_SIZE];
        snprintf(message1, sizeof(message1), "%s|%s|%s", nonce, receiver, Ks);
        char encrypted1[BUFFER_SIZE];
        strcpy(encrypted1, message1);
        xor_crypt(encrypted1, Kas, strlen(message1), strlen(Kas));

        // Construct message2: Ks|A
        char message2[BUFFER_SIZE];
        snprintf(message2, sizeof(message2), "%s|%s", Ks, requester);
        char encrypted2[BUFFER_SIZE];
        strcpy(encrypted2, message2);
        xor_crypt(encrypted2, Kbs, strlen(message2), strlen(Kbs));

        // Combine both with separator
        char full[BUFFER_SIZE * 2];
        snprintf(full, sizeof(full), "%s||%s", encrypted1, encrypted2);

        send(client_fd, full, strlen(full), 0);
        printf("Sent encrypted response to A.\n");

        close(client_fd);
    }

    close(server_fd);
    return 0;
}
