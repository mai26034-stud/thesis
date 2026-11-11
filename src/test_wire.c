#include "wire.h"
#include <stdio.h>
#include <string.h>

static int test_wire_roundtrip(void);
static int test_wire_stats(void);
static int test_wire_sequential(void);

int main(void){
    int failures = 0;
    failures += test_wire_roundtrip();
    failures += test_wire_stats();
    failures += test_wire_sequential();
    return failures;
}

static int test_wire_roundtrip(){
    uint8_t buf[256];
    wire_stats_t stats;
    size_t written;
    size_t content_len_out;
    size_t consumed;
    uint8_t type_out;
    const uint8_t *content_out;
    wire_stats_init(&stats);
    const uint8_t content[] = "test-content";
    kem_status_t s = wire_write(WIRE_CLIENT_HELLO, content, 12, buf, sizeof(buf), &written, &stats);
    if(s != KEM_SUCCESS) return 1;
    s = wire_read(buf, written, &type_out, &content_out, &content_len_out, &consumed);
    if(s != KEM_SUCCESS) return 2;
    if(type_out == WIRE_CLIENT_HELLO && content_len_out == 12 && memcmp(content_out, content, 12) == 0 && consumed == written) return 0;
    else return 3;
}

static int test_wire_stats(){
    uint8_t buf[256];
    uint8_t big[100];
    memset(big, 'X', 100);
    wire_stats_t stats;
    size_t written;
    wire_stats_init(&stats);
    const uint8_t content[] = "test-content";
    kem_status_t s = wire_write(WIRE_CLIENT_HELLO, content, 12, buf, sizeof(buf), &written, &stats);
    if(s != KEM_SUCCESS) return 1;
    s = wire_write(WIRE_CLIENT_AUTH, big, 100, buf, sizeof(buf), &written, &stats);
    if(s != KEM_SUCCESS) return 2;
    if(stats.bytes_by_type[WIRE_CLIENT_HELLO] == 17 && stats.bytes_by_type[WIRE_CLIENT_AUTH] == 105 && stats.total_bytes == 122) return 0;
    else return 3;
}

static int test_wire_sequential(void){
    uint8_t buf[256];
    wire_stats_t stats;
    size_t len1, len2;
    size_t consumed1, consumed2;
    size_t w1, w2;
    uint8_t type1, type2;
    const uint8_t *c1, *c2;
    const uint8_t content[] = "test-content";
    const uint8_t content2[] = "good-content";

    wire_stats_init(&stats);
    kem_status_t s = wire_write(WIRE_CLIENT_HELLO, content, 12, buf, sizeof(buf), &w1, &stats);
    if(s != KEM_SUCCESS){
        printf("[wire-seq] FAILED: 1st writing.\n");
        return 1;
    }
    s = wire_write(WIRE_SERVER_HELLO, content2, 12, buf + w1, sizeof(buf) - w1, &w2, &stats);
    if(s != KEM_SUCCESS){
        printf("[wire-seq] FAILED: 2nd writing.\n");
        return 1;
    }
    size_t total = w1 + w2;
    s = wire_read(buf, total, &type1, &c1, &len1, &consumed1);
    if(s != KEM_SUCCESS){
        printf("[wire-seq] FAILED: 1st reading.\n");
        return 1;
    }
    if(consumed1 != w1){
        printf("[wire-seq] FAILED: 1st consumed part.\n");
        return 1;
    }
    s = wire_read(buf + consumed1, total - consumed1, &type2, &c2, &len2, &consumed2);
    if(s != KEM_SUCCESS){
        printf("[wire-seq] FAILED: 2nd reading.\n");
        return 1;
    }
    if(type2 == WIRE_SERVER_HELLO && len2 == 12 && memcmp(c2, content2, 12) == 0){
        printf("[wire-seq] OK\n");
        return 0;
    }
    printf("[wire-seq] FAILED: 2nd message mismatch.\n");
    return 1;
}
