// clienta.c - initiates request, receives session key, performs authentication
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 8000
#define CLIENT_B_PORT 9001
#define BUFFER_SIZE 2048

const char *Kas = "ASecretKey12345"; // Shared with server

void xor_crypt(char *data, const char *key, size_t len, size_t key_len) {
    for (size_t i = 0; i < len; ++i)
        data[i] ^= key[i % key_len];
}

int main() {
    int sock;
    struct sockaddr_in server_addr;
    char buffer[BUFFER_SIZE];

    sock = socket(AF_INET, SOCK_STREAM, 0);
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr);

    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection to server failed");
        return 1;
    }

    char request[] = "A|B|12345";
    send(sock, request, strlen(request), 0);
    printf("Sent request to server: %s\n", request);

    int n = recv(sock, buffer, BUFFER_SIZE - 1, 0);
    buffer[n] = '\0';

    // Separate message1 and message2
    char *split = strstr(buffer, "||");
    if (!split) {
        printf("Failed to split server message.\n");
        close(sock);
        return 1;
    }
    *split = '\0';
    char *enc1 = buffer;
    char *enc2 = split + 2;

    // Decrypt message1
    char dec1[BUFFER_SIZE];
    strcpy(dec1, enc1);
    xor_crypt(dec1, Kas, strlen(enc1), strlen(Kas));
    printf("Decrypted message1: %s\n", dec1);

    char nonce[50], target[50], Ks[50];
    sscanf(dec1, "%49[^|]|%49[^|]|%49s", nonce, target, Ks);

    // Connect to B
    int sock_b;
    struct sockaddr_in b_addr;
    sock_b = socket(AF_INET, SOCK_STREAM, 0);
    b_addr.sin_family = AF_INET;
    b_addr.sin_port = htons(CLIENT_B_PORT);
    inet_pton(AF_INET, "127.0.0.1", &b_addr.sin_addr);

    if (connect(sock_b, (struct sockaddr *)&b_addr, sizeof(b_addr)) < 0) {
        perror("Connect to B failed");
        return 1;
    }

    // Send encrypted message2 to B
    send(sock_b, enc2, strlen(enc2), 0);

    // Receive challenge Nb
    n = recv(sock_b, buffer, BUFFER_SIZE - 1, 0);
    buffer[n] = '\0';
    char decrypted_Nb[BUFFER_SIZE];
    strcpy(decrypted_Nb, buffer);
    xor_crypt(decrypted_Nb, Ks, strlen(decrypted_Nb), strlen(Ks));

    int Nb = atoi(decrypted_Nb);
    int Nb_minus_1 = Nb - 1;
    char Nb_minus_1_str[50];
    snprintf(Nb_minus_1_str, sizeof(Nb_minus_1_str), "%d", Nb_minus_1);
    char encrypted_response[BUFFER_SIZE];
    strcpy(encrypted_response, Nb_minus_1_str);
    xor_crypt(encrypted_response, Ks, strlen(Nb_minus_1_str), strlen(Ks));

    send(sock_b, encrypted_response, strlen(Nb_minus_1_str), 0);
    printf("Needham-Schroeder protocol complete.\n");

    close(sock);
    close(sock_b);
    return 0;
}
