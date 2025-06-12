// clientb.c - receives session key from A, mutual authentication
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>

#define CLIENT_B_PORT 9001
#define BUFFER_SIZE 1024

const char *Kbs = "BSecretKey54321"; // Shared with server

void xor_crypt(char *data, const char *key, size_t len, size_t key_len) {
    for (size_t i = 0; i < len; ++i)
        data[i] ^= key[i % key_len];
}

int main() {
    int server_fd, client_fd;
    struct sockaddr_in addr;
    socklen_t addrlen = sizeof(addr);
    char buffer[BUFFER_SIZE];

    srand(time(NULL));

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(CLIENT_B_PORT);

    bind(server_fd, (struct sockaddr *)&addr, sizeof(addr));
    listen(server_fd, 3);

    printf("Client B listening on port %d...\n", CLIENT_B_PORT);

    client_fd = accept(server_fd, (struct sockaddr *)&addr, &addrlen);
    int n = recv(client_fd, buffer, BUFFER_SIZE - 1, 0);
    buffer[n] = '\0';
    printf("Received encrypted session key: %s\n", buffer);

    char decrypted[BUFFER_SIZE];
    strcpy(decrypted, buffer);
    xor_crypt(decrypted, Kbs, strlen(decrypted), strlen(Kbs));

    char Ks[50], requester[50];
    if (sscanf(decrypted, "%49[^|]|%49s", Ks, requester) != 2) {
        printf("Failed to parse Ks|A\n");
        close(client_fd);
        return 1;
    }

    printf("Extracted Ks: %s from A: %s\n", Ks, requester);

    // Generate challenge Nb
    int Nb = rand() % 9000 + 1000;
    char Nb_str[50];
    snprintf(Nb_str, sizeof(Nb_str), "%d", Nb);

    char encrypted_Nb[BUFFER_SIZE];
    strcpy(encrypted_Nb, Nb_str);
    xor_crypt(encrypted_Nb, Ks, strlen(Nb_str), strlen(Ks));
    send(client_fd, encrypted_Nb, strlen(Nb_str), 0);

    // Receive Nb-1
    n = recv(client_fd, buffer, BUFFER_SIZE - 1, 0);
    buffer[n] = '\0';
    char decrypted_resp[BUFFER_SIZE];
    strcpy(decrypted_resp, buffer);
    xor_crypt(decrypted_resp, Ks, strlen(buffer), strlen(Ks));

    if (atoi(decrypted_resp) == Nb - 1)
        printf("Authentication success.\n");
    else
        printf("Authentication failed.\n");

    close(client_fd);
    close(server_fd);
    return 0;
}
