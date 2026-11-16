#include "handshake.h"
#include "channel.h"
#include "transport.h"
#include "files.h"
#include "metrics.h"
#include "mqtt.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>

#define CLIENT_ID "D001"
#define TOPIC "tele/D001/3303/0/5700"

static int parse_num(const char *s, long min, long max, long *out){
  char *end;
  long v =strtol(s, ^end, 10);
  if(*s == '\0' || *end != '\0' || v < min || v > max) return 1;
  *out = v;
  return 0;
}

static kem_status_t recv_app(int fd, record_dir_t *rx, uint8_t *buf, size_t cap, size_t *n){
  uint8_t ct;
  if(channel_recv(fd, rx, buf, cap, n, &ct) != KEM_SUCCESS) return KEM_ERROR;
  if(ct != REC_TYPE_APPDATA) return KEM_ERROR;
  return KEM_SUCCESS;
}

static int one_session(const char *kem_name, const char *host, uint16_t port, const uint8_t *ca_pub, int iteration){
  uint8_t connect_pkt[64];
  uint8_t pkt[256];
  uint8_t resp[REC_MAX_PLAIN + 256];
  char payload[128];
  size_t connect_len = 0;
  size_t pkt_len = 0;
  size_t n = 0;
  uint8_t rc = 0xFF;
  uint16_t pid = 0;
  uint16_t packet_id = (uint16_t)(((iteration - 1) % 65535) + 1);
  record_dir_t app_tx, app_rx;
  wire_stats_t stats;
  timings_t tm;
  wire_stats_init(&stats);
  timings_init(&tm);
  if(mqtt_build_connect(CLIENT_ID, 60, connect_pkt, sizeof(connect_pkt), &connect_len) != KEM_SUCCESS) return 1;
  uint64_t t_start = metrics_now();
  int fd = transport_client
}
