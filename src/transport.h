#ifndef TRANSPORT_H
#define TRANSPORT_H
#include <stddef.h>
#include "kem.h"

int transport_server_accept(uint16_t port);
int transport_client_connect(const char *host, uint16_t port);
kem_status_t transport_send(int fd, const uint8_t *buf, size_t len);
kem_status_t transport_recv(int fd, uint8_t *buf, size_t len);
void transport_close(int fd);

#endif
