#include "baseline.h"
#include "transport.h"
#include "wire.h"
#include "metrics.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>

#define WARMUP 3
#define ITERATIONS 30
#define CA_CERT "~/thesis/certs/ca-cert.pem"
#define SRV_CERT "~/thesis/certs/server-cert.pem"
#define SRV_KEY "~/thesis/certs/server-key.pem"

static int one_baseline(uint16_t port, int iteration){
  fflush(stdout);
  pid_t pid = fork();
  if(pid < 0) return 1;

  if(pid == 0){
      int fd = transport_server_accept(port);
      if(fd < 0) exit(1);
      uint8_t key[32];
      size_t bytes = 0;
      timings_t tm;
      timings_init(&tm);
      if(baseline_server(fd, SRV_CERT, SRV_KEY, key, &bytes, &tm) != KEM_SUCCESS){
          transport_close(fd);
          exit(1);
      }
      if(iteration > 0){
          wire_stats_t st;
          wire_stats_init(&st);
          st.total_bytes = bytes;
          metrics_csv_row(stdout, "baseline", "server", iteration, &tm, &st);
      }
      transport_close(fd);
      fflush(stdout);
      exit(0);
  }
  
  int fd = -1;
  for(int attempt = 0; attempt < 50 && fd < 0; attempt++){
      fd = transport_client_connect("127.0.0.1", port);
      if(fd < 0) usleep(10000);
  }
  if(fd < 0){
      waitpid(pid, NULL, 0);
      return 1;
  }
  uint8_t key[32];
  size_t bytes = 0;
  timings_t tm;
  timings_init(&tm);
  int ok = 0;
  if(baseline_client(fd, CA_CERT, key, &bytes, &tm) != KEM_SUCCESS){
    ok = 1;
  }else if(iteration > 0){
    wire_stats_t st;
    wire_stats_init(&st);
    st.total_bytes = bytes;
    metrics_csv_row(stdout, "baseline", "client", iteration, &tm, &st);
  }
  transport_close(fd);
  waitpid(pid, NULL, 0);
  return ok;
}

int main(void){
  int failures = 0;
  metrics_csv_header(stdout);
  fflush(stdout);
  for(int i = 0; i < WARMUP + ITERATIONS; i++){
    int iter = (i < WARMUP) ? -1 : (i - WARMUP + 1);
    if(one_baseline(19600 + i, iter) != 0) failures++;
  }
  return failures;
}
