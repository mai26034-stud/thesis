#include "handshake.h"
#include "channel.h"
#include "transport.h"
#include "files.h"
#include "metrics.h"
#include "kem.h"
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/memory.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>
#include <signal.h>
#include <sys/socket.h>

#define BROKER_HOST "127.0.0.1"
#define BROKER_PORT 1883

static int parse_num(const char *s, long min, long max, long *out){
    char *end;
    long v = strtol(s, &end, 10);
    if(*s == '\0' || *end != '\0' || v < min || v > max) return 1;
    *out = v;
    return 0;
}

static int relay(int dev_fd, int broker_fd, record_dir_t *tx, record_dir_t *rx){
    uint8_t buf[REC_MAX_PLAIN + 256];
    struct pollfd fds[2];
    fds[0].fd = dev_fd;
    fds[0].events = POLLIN;
    fds[1].fd = broker_fd;
    fds[1].events = POLLIN;
    for(;;){
        if(poll(fds, 2, -1) < 0) return 1;
        if(fds[0].revents & (POLLIN | POLLHUP | POLLERR)){
            size_t n;
            uint8_t ct;
            if(channel_recv(dev_fd, rx, buf, sizeof(buf), &n, &ct) != KEM_SUCCESS) return 0;
            if(ct != REC_TYPE_APPDATA) return 1;
            if(n > 0 && transport_send(broker_fd, buf, n) != KEM_SUCCESS) return 1;
        }
        if(fds[1].revents & (POLLIN | POLLHUP | POLLERR)){
            ssize_t n = recv(broker_fd, buf, REC_MAX_PLAIN, 0);
            if(n <= 0) return 0;
            if(channel_send(dev_fd, tx, REC_TYPE_APPDATA, buf, (size_t)n, NULL) != KEM_SUCCESS) return 1;
        }
    }
}

int main(int argc, char **argv){}