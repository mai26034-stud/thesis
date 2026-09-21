#include "transport.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>

int transport_client_connect(const char *host, uint16_t port){
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if(fd < 0) return -1;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    if(inet_pton(AF_INET, host, &addr.sin_addr) != 1){
        close(fd);
        return -1;
    }
    if(connect(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0){
        close(fd);
        return -1;
    }
    return fd;
}

int transport_server_accept(uint16_t port){
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if(listen_fd < 0) return -1;

    int opt = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if(bind(listen_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0){
        close(listen_fd);
        return -1;
    }
    if(listen(listen_fd, 1) < 0){
        close(listen_fd);
        return -1;
    }

    int conn_fd = accept(listen_fd, NULL, NULL);
    close(listen_fd);
    if(conn_fd < 0) return -1;
    return conn_fd;
}

kem_status_t transport_send(int fd, const uint8_t *buf, size_t len){
    if(buf == NULL || fd < 0) return KEM_ERROR;
    size_t sent = 0;
    while(sent < len){
        ssize_t n = send(fd, buf + sent, len - sent, 0);
        if(n <= 0) return KEM_ERROR;
        sent += (size_t)n;
    }
    return KEM_SUCCESS;
}

kem_status_t transport_recv(int fd, uint8_t *buf, size_t len){
    if(buf == NULL || fd < 0) return KEM_ERROR;
    size_t received = 0;
    while(received < len){
        ssize_t n = recv(fd, buf + received, len - received, 0);
        if(n <= 0) return KEM_ERROR;
        received += (size_t)n;
    }
    return KEM_SUCCESS;
}

void transport_close(int fd){
    if(fd >= 0) close(fd);
}
