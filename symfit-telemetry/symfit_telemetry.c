#include "symfit_telemetry.h"
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

static int socket_desc = -1;
static pthread_mutex_t telemetry_lock = PTHREAD_MUTEX_INITIALIZER;
char telemetry_enabled = 0;

// TO DO: Should ip_addr be a const?
void telemetry_init(const char * ip_addr, unsigned short port) {
    // Only initialize a socket if we're not already connected!
    if (socket_desc < 0) {
        if (ip_addr == NULL) {
            fprintf(stderr, "ERROR: telemetry_init() called with null IP address!\n");
            return;
        }
        socket_desc = socket(AF_INET, SOCK_STREAM, 0);
        if (socket_desc == -1) {
            fprintf(stderr, "ERROR: Socket creation failed!\n");
            return;
        }
        struct sockaddr_in server_addr;
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(port);
        server_addr.sin_addr.s_addr = inet_addr(ip_addr);
        if (connect(socket_desc, (struct sockaddr *)&server_addr, sizeof(server_addr)) == 0) telemetry_enabled = 1;
    }
    else {
        fprintf(stderr, "ERROR: Socket initialization attempted when already connected!\n");
        return;
    }
    return;
}

void telemetry_shutdown() {
    if (socket_desc >= 0) {
        close(socket_desc);
        socket_desc = -1; // So the initializer function knows this is unassigned again
    }
    return;
}

void telemetry_send(const char* json) {
    if (json == NULL) {
        fprintf(stderr, "ERROR: Null string pointer sent to telemetry_send()!\n");
        return;
    }
    if (socket_desc < 0) {
        fprintf(stderr, "ERROR: telemetry_send() invoked with bad socket descriptor!\n");
        return;
    }
    
    /*
     * We can compute these while we potentially wait for the mutex lock to release.
     * Practically speaking, this probably doesn't make much difference, but we should spend
     * as little time inside the lock as possible.
     */
    uint32_t json_len = strlen(json);
    uint32_t net_len = htonl(json_len);
    pthread_mutex_lock(&telemetry_lock);
    send(socket_desc, &net_len, sizeof(net_len), 0);
    send(socket_desc, json, json_len, 0);
    pthread_mutex_unlock(&telemetry_lock);
}
