#include "baseline.h"
#include "transport.h"
#include "metrics.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>
#include <signal.h>
#include <sys/socket.h>

#define BROKER_HOST "127.0.0.1"
#define BROKER_PORT 1883
#define BUF_SZ 16384

static int parse_num(const char *s, long min, long max, long *out){
  char *end;
  long v = strtol(s, &end, 10);
  if(*s == '\0' || *end != '\0' || v < min || v > max) return 1;
  *out = v;
  return 0;
}

static int relay(baseline_conn_t *c, int broker_fd){
  uint8_t buf[BUF_SZ];
  struct pollfd fds[2];
  fds[0].fd = c->io.fd;
  fds[0].events = POLLIN;
  fds[1].fd = broker_fd;
  fds[1].events = POLLIN;
  for(;;){
    int pending = baseline_pending(c);
    if(poll(fds, 2, (pending > 0) ? 0 : -1) < 0) return 1;
    if(pending > 0 || (fds[0].revents & (POLLIN | POLLHUP | POLLERR))){
      size_t n;
      if(baseline_read(c, buf, sizeof(buf), &n) != KEM_SUCCESS) return 0;
      if(transport_send(broker_fd, buf, n) != KEM_SUCCESS) return 1;
    }
    if(fds[1].revents & (POLLIN | POLLHUP | POLLERR)){
      ssize_t n = recv(broker_fd, buf, sizeof(buf), 0);
      if(n <= 0) return 0;
      if(baseline_write(c, buf, (size_t)n) != KEM_SUCCESS) return 1;
    }
  }
}

int main(int argc, char **argv){
  if(argc < 3 || argc > 4){
    fprintf(stderr, "usage: %s <port> <certs_dir> [connections]\n", argv[0]);
    return 1;
  }
  long port;
  long count = 0;
  if(parse_num(argv[1], 1, 65535, &port) != 0 || (argc == 4 && parse_num(argv[3], 0, 1000000, &count) != 0)){
    fprintf(stderr, "[getaway baseline] FAIL: bad port or connection count\n");
    return 1;
  }
  char cert[512];
  char key[512];
  int n1 = snprintf(cert, sizeof(cert), "%s/server-cert.pem", argv[2]);
  int n2 = snprintf(key, sizeof(key), "%s/server-key.pem", argv[2]);
  if(n1 <= 0 || (size_t)n1 >= sizeof(cert) || n2 <= 0 || (size_t)n2 >= sizeof(key)){
    fprintf(stderr, "[getaway baseline] FAIL: path too long\n");
    return 1;
  }
  signal(SIGPIPE, SIG_IGN);
  wolfSSL_Init();
  WOLFSSL_CTX *ctx = baseline_server_ctx(cert, key);
  if(ctx == NULL){
    fprintf(stderr, "[getaway baseline] FAIL: can not load certificate or key\n");
    wolfSSL_Cleanup();
    return 1;
  }
  int lfd = transport_listen((uint16_t)port);
  if(lfd < 0){
    fprintf(stderr, "[getaway baseline] FAIL: can not load certificate or key\n");
    wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();
    return 1;
  }
  metrics_csv_header(stdout);
  fflush(stdout);
  for(long i = 1; count == 0 || i <= count; i++){
    int fd = transport_accept(lfd);
    if(fd < 0) continue;
    baseline_conn_t conn;
    wire_stats_t stats;
    timings_t tm;
    wire_stats_init(&stats);
    timings_init(&tm);
    if(baseline_accept(ctx, fd, &conn, &stats, &tm) != KEM_SUCCESS){
      fprintf(stderr, "[getaway baseline] handshake failed (connection %ld)\n", i);
      transport_close(fd);
      return 1;
    }
    int bfd = transport_client_connect(BROKER_HOST, BROKER_PORT);
    if(bfd < 0){
      fprintf(stderr, "[getaway baseline] can not connect to broker (connection %ld)\n", i);
    }else{
      if(relay(&conn, bfd) != 0) fprintf(stderr, "[getaway baseline] relay error (connection %ld)\n", i);
      transport_close(bfd);
    }
    metrics_csv_row(stdout, "baseline", "gateway", (int)i, &tm, &stats);
    fflush(stdout);
    baseline_free(&conn);
    transport_close(fd);
  }
  transport_close(lfd);
  wolfSSL_CTX_free(ctx);
  wolfSSL_Cleanup();
  return 0;
}
