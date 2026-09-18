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

    if(bind(listen_fc, (struct sockaddr*)&addr, sizeof(addr)) < 0){
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
