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
  long v =strtol(s, &end, 10);
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
  int fd = transport_client_connect(host, port);
  if(fd < 0){
    fprintf(stderr, "[publisher] connect failed (iteration %d)\n", iteration);
    return 1;
  }
  if(handshake_client(fd, kem_name, ca_pub, connect_pkt, connect_len, &app_tx, &app_rx, &stats, &tm) != KEM_SUCCESS){
    fprintf(stderr, "[publisher] handshake failed (iteration %d)\n", iteration);
    transport_close(fd);
    return 1;
  }
  kem_status_t r = recv_app(fd, &app_rx, resp, sizeof(resp), &n);
  if(r == KEM_SUCCESS) r = mqtt_parse_connack(resp, n, &rc);
  if(r == KEM_SUCCESS && rc != 0) r = KEM_ERROR;
  if(r == KEM_SUCCESS){
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    unsigned long long ms = (unsigned long long)ts.tv_sec *1000ULL + (unsigned long long)(ts.tv_nsec/1000000);
    int plen = snprintf(payload, sizeof(payload), "{\"e\":[{\"v\":%.1f}],\"tmstp\":%llu}}", 23.4, ms);
    if(plen <= 0 || (size_t)plen >= sizeof(payload)) r = KEM_ERROR;
    if(r == KEM_SUCCESS) r = mqtt_build_publish(TOPIC, (const uint8_t *)payload, (size_t)plen, 1, packet_id, pkt, sizeof(pkt), &pkt_len);
  }
  if(r == KEM_SUCCESS) r = channel_send(fd, &app_tx, REC_TYPE_APPDATA, pkt, pkt_len, NULL);
  if(r == KEM_SUCCESS) r = recv_app(fd, &app_rx, resp, sizeof(resp), &n);
  if(r == KEM_SUCCESS) r = mqtt_parse_puback(resp, n, &pid);
  if(r == KEM_SUCCESS && pid != packet_id) r = KEM_ERROR;
  if(r == KEM_SUCCESS) tm.puback_ns = metrics_now() - t_start;
  if(r == KEM_SUCCESS){
    if(mqtt_build_disconnect(pkt, sizeof(pkt), &pkt_len) == KEM_SUCCESS){
      channel_send(fd, &app_tx, REC_TYPE_APPDATA, pkt, pkt_len, NULL);
    }
    metrics_csv_row(stdout, kem_name, "publisher", iteration, &tm, &stats);
    fflush(stdout);
  }else{
    fprintf(stderr, "[publisher] MQTT exchange failed (iteration %d)\n", iteration);
  }
  record_clear(&app_tx);
  record_clear(&app_rx);
  transport_close(fd);
  return (r == KEM_SUCCESS) ? 0 : 1;
}

int main(int argc, char **argv){
  if(argc != 6){
    fprintf(stderr, "usage: %s <KEM> <host> <port> <ca.pub> <connections>\n", argv[0]);
    return 1;
  }
  long port, count;
  if(parse_num(argv[3], 1, 65535, &port) != 0 || parse_num(argv[5], 1, 1000000, &count) != 0){
    fprintf(stderr, "[publisher] FAIL: bad port or connection count\n");
    return 1;
  }
  signal(SIGPIPE, SIG_IGN);
  uint8_t ca_pub[CA_PUB_LEN];
  size_t got = 0;
  if(file_read(argv[4], ca_pub, sizeof(ca_pub), &got) != KEM_SUCCESS || got != CA_PUB_LEN){
    fprintf(stderr, "[publisher] FAIL: can not read CA public key\n");
    return 1;
  }
  metrics_csv_header(stdout);
  fflush(stdout);
  int failures = 0;
  for(long i = 1; i <= count; i++){
    failures += one_session(argv[1], argv[2], (uint16_t)port, ca_pub, (int)i);
  }
  return (failures > 0) ? 1 : 0;
}
