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
#define CA_CERT "../certs/ca-cert.pem"
#define SRV_CERT "../certs/server-cert.pem"
#define SRV_KEY "../certs/server-key.pem"

static int one_baseline(uint16_t port, int iteration){
  fflush(stdout);
  pid_t pid = fork();
  if(pid < 0) return 1;

  if(pid == 0){
      WOLFSSL_CTX *ctx = baseline_server_ctx(SRV_CERT, SRV_KEY);
      if(ctx == NULL) exit(1);
      int fd = transport_server_accept(port);
      if(fd < 0){
        wolfSSL_CTX_free(ctx);
        exit(1);
      }
      baseline_conn_t conn;
      wire_stats_t st;
      timings_t tm;
      wire_stats_init(&st);
      timings_init(&tm);
      int rc = 0;
      if(baseline_accept(ctx, fd, &conn, &st, &tm) != KEM_SUCCESS){
          rc = 1;
      }else{
          if(iteration > 0) metrics_csv_row(stdout, "baseline", "server", iteration, &tm, &st);
          baseline_free(&conn);
      }
      transport_close(fd);
      wolfSSL_CTX_free(ctx);
      fflush(stdout);
      exit(rc);
  }
  
  WOLFSSL_CTX *ctx = baseline_client_ctx(CA_CERT);
  if(ctx == NULL){
    waitpid(pid, NULL, 0);
    return 1;
  }
  int fd = -1;
  for(int attempt = 0; attempt < 50 && fd < 0; attempt++){
      fd = transport_client_connect("127.0.0.1", port);
      if(fd < 0) usleep(10000);
  }
  if(fd < 0){
    wolfSSL_CTX_free(ctx);
      waitpid(pid, NULL, 0);
      return 1;
  }
  baseline_conn_t conn;
  wire_stats_t st;
  timings_t tm;
  wire_stats_init(&st);
  timings_init(&tm);
  int ok = 0;
  if(baseline_connect(ctx, fd, &conn, &st, &tm) != KEM_SUCCESS){
    ok = 1;
  }else{
    if(iteration > 0) metrics_csv_row(stdout, "baseline", "client", iteration, &tm, &st);
    baseline_free(&conn);
  }
  transport_close(fd);
  wolfSSL_CTX_free(ctx);
  int status;
  waitpid(pid, &status, 0);
  if(!WIFEXITED(status) || WEXITSTATUS(status) != 0) ok = 1;
  return ok;
}

int main(void){
  wolfSSL_Init();
  int failures = 0;
  metrics_csv_header(stdout);
  fflush(stdout);
  for(int i = 0; i < WARMUP + ITERATIONS; i++){
    int iter = (i < WARMUP) ? -1 : (i - WARMUP + 1);
    if(one_baseline(19600 + i, iter) != 0) failures++;
  }
  wolfSSL_Cleanup();
  return failures;
}
