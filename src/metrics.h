#ifndef METRICS_H
#define METRICS_H
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include "wire.h"

typedef struct{
    uint64_t eph_keypair_ns;
    uint64_t eph_encaps_ns;
    uint64_t eph_decaps_ns;
    uint64_t cred_verify_ns;
    uint64_t auth_encaps_ns;
    uint64_t auth_decaps_ns;
    uint64_t key_schedule_ns;
    uint64_t total_ns;
    uint64_t client_ready_ns;
    uint64_t puback_ns;
} timings_t;

uint64_t metrics_now(void);
void timings_init(timings_t *tm);
void metrics_csv_header(FILE *f);
void metrics_csv_row(FILE *f, const char *config, const char *role, int iteration, const timings_t *tm, const wire_stats_t *st);

#endif
