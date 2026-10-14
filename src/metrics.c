#include "metrics.h"
#include <time.h>
#include <string.h>

uint64_t metrics_now(void){
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

void timings_init(timings_t *tm){
  if(tm == NULL) return;
  memset(tm, 0, sizeof(*tm));
  return;
}

void metrics_csv_header(FILE *f){
  if(f == NULL) return;
  fprintf(f, "config,role,iteration,""eph_keypair_ns,eph_encaps_ns,eph_decaps_ns,""cred_verify_ns,auth_encaps_ns,auth_decaps_ns,""key_schedule_ns,total_ns,""bytes_total,bytes_client_auth,bytes_server_auth\n");
}

void metrics_csv_row(FILE *f, const char *config, const char *role, int iteration, const timings_t *tm, const wire_stats_t *st){
  if(){}
}
