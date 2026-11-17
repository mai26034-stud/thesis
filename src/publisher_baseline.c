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
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    unsigned long long ms = (unsigned long long)ts.tv_sec * 1000ULL + (unsigned long long)(ts.tv_nsec/1000000);
    int plen = snprintf(payload, sizeof(payload), "{\"e\":[{\"v\":%.1f}],\"tmstp\":%llu}", 23.4, ms);
    if(plen <= 0 || (size_t)plen >= sizeof(paylod)) r = KEM_ERROR;
    if(r == KEM_SUCCESS) r = mqtt_build_publish(TOPIC, (const uint8_t *)payload, (size_t)plen, 1, packet_id, pkt, sizeof(pkt), &pkt_len);
  }
  if(r == KEM_SUCCESS) r = baseline_write(&conn, pkt, pkt_len);
  if(r == KEM_SUCCESS) r = baseline_read(&conn, resp, sizeof(resp), &n);
  if(r == KEM_SUCCESS) r = mqtt_parse_puback(resp, n, &pid);
  if(r == KEM_SUCCESS && pid != packet_id) r = KEM_ERROR;
  if(r == KEM_SUCCESS) tm.puback_ns = metrics_now() - t_start;
  if(r == KEM_SUCCESS){
    if(mqtt_build_disconnect)pkt, sizeof(pkt), &pkt_len) == KEM_SUCCESS){
      baseline_write(&conn, pkt, pkt_len);
    }
    metrics_csv_row(stdout, "baseline", "publisher", iteration, &tm, &stats);
    fflush(stdout);
  }else{
    fprintf(stderr, "[publisher baseline] MQTT exchange failed (iteration %d)\n", iteration);
  }
  baseline_free(&conn);
  transport_close(fd);
  return (r == KEM_SUCCESS) ? 0 : 1;
}

int main(int argc, char **argv){
  if(argc != 5){
    fprintf(stderr, "usage: %s <host> <port> <ca_cert.pem> <connections>\n", argv[0]);
    return 1;
  }
  long port, count;
  if(parse_num(argv[2], 1, 65535, &port) != 0 || parse_num(argv[4], 1, 1000000, &count) != 0){
    fprintf(stderr, "[publisher baseline] FAIL: bad port or connection count\n");
    return 1;
  }
  signal(SIGPIPE, SIG_IGN);
  wolfSSL_Init();
  WOLFSSL_CTX *ctx = baseline_client_ctx(argv[3]);
  if(ctx == NULL){
    fprintf(stderr, "[publisher baseline] FAIL: can not load CA certificate\n");
    return 1;
  }
  metrics_csv_header(stdout);
  fflush(stdout);
  int failures = 0;
  for(long i = 1; i <= count; i++){
    failures += one_session(ctx, argv[1], (uint16_t)port, (int)i);
  }
  wolfSSL_CTX_free(ctx);
  wolfSSL_Cleanup();
  return (failures > 0) ? 1 : 0;
}
