#include "metrics.h"
#include <time.h>
#include <string.h>
#include <sys/resource.h>

uint64_t metrics_now(void){
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

uint64_t metrics_cpu_now(void){
  struct timespec ts;
  clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ts);
  return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

long metrics_max_rss_kb(void){
  struct rusage ru;
  if(getrusage(RUSAGE_SELF, &ru) != 0) return -1;
  return ru.ru_maxrss;
}

void timings_init(timings_t *tm){
  if(tm == NULL) return;
  memset(tm, 0, sizeof(*tm));
  return;
}

void metrics_csv_header(FILE *f){
  if(f == NULL) return;
  fprintf(f, "config,role,iteration,""eph_keypair_ns,eph_encaps_ns,eph_decaps_ns,""cred_verify_ns,auth_encaps_ns,auth_decaps_ns,""key_schedule_ns,total_ns,client_ready_ns,puback_ns,cpu_ns,max_rss_kb,""bytes_total,bytes_client_auth,bytes_server_auth\n");
}

void metrics_csv_row(FILE *f, const char *config, const char *role, int iteration, const timings_t *tm, const wire_stats_t *st){
  if(f == NULL || config == NULL || role == NULL || tm == NULL || st == NULL) return;
  fprintf(f, "%s,%s,%d,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%ld,%zu,%zu,%zu\n", config, role, iteration, (unsigned long long)tm->eph_keypair_ns, (unsigned long long)tm->eph_encaps_ns, (unsigned long long)tm->eph_decaps_ns, (unsigned long long)tm->cred_verify_ns, (unsigned long long)tm->auth_encaps_ns, (unsigned long long)tm->auth_decaps_ns, (unsigned long long)tm->key_schedule_ns, (unsigned long long)tm->total_ns, (unsigned long long)tm->client_ready_ns, (unsigned long long)tm->puback_ns, (unsigned long long)tm->cpu_ns, metrics_max_rss_kb(), st->total_bytes,st->bytes_by_type[WIRE_CLIENT_AUTH],st->bytes_by_type[WIRE_SERVER_AUTH]);
  return;
}
