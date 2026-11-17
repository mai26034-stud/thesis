#include "baseline.h"
#include "transport.h"
#include "metrics.h"
#include "mqtt.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>

#define CLIENT_ID "D001"
#define TOPIC "tele/D001/3303/0/5700"
#define BUF_SZ 16384

static int parse_num(const char *s, long min, long max, long *out){
  char *end;
  long v = strtol(s, &end, 10);
  if(*s == '\0' || *end != '\0' || v < min || v > max) return 1;
  *out = v;
  return 0;
}

static int one_session(WOLFSSL_CTX *ctx, const char *host, uint16_t port, int iteration){
  uint8_t connect_pkt[64];
  uint8_t pkt[256];
  uint8_t resp[BUF_SZ];
  char payload[128];
  size_t connect_len = 0;
  size_t pkt_len = 0;
  size_t n =0;
  uint8_t rc = 0xFF;
  uint16_t pid = 0;
  uint16_t packet_id = (uint16_t)(((iteration - 1) % 65535) + 1);
  baseline_conn_t conn;
  wire_stats_t stats;
  timings_t tm;
  wire_stats_init(&conn);
  timings_init(&tm);
  if(mqtt_build_connect(CLIENT_ID, 60, connect_pkt, sizeof(connect_pkt), &connect_len) != KEM_SUCCESS) return 1;
  uint64_t t_start = metrics_now();
  int fd = transport_client_connect(host, port);
  if(fd < 0){
    fprintf(stderr, "[publisher baseline] connect failed (iteration %d)\n", iteration);
    return 1;
  }
  if(baseline_connect(ctx, fd, &conn, &stats, &tm) != KEM_SUCCESS){
    fprintf(stderr, "[publisher baseline] connect failed (iteration %d)\n", iteration);
    transport_close(fd);
    return 1;
  }
  kem_status_t r = baseline_write(&conn, connect_pkt, connect_len);
  if(r == KEM_SUCCESS) r = baseline_read(&conn, resp, sizeof(resp), &n);
  if(r == KEM_SUCCESS) r = mqtt_parse_connack(resp, n, &rc);
  if(r == KEM_SUCCESS && rc != 0) r = KEM_ERROR;
  if(r == KEM_SUCCESS){
    
  }
}
