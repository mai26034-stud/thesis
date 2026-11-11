#include "record.h"
#include <stdio.h>
#include <string.h>

static const uint8_t rfc_c_hs[32] = {
    0xb3, 0xed, 0xdb, 0x12, 0x6e, 0x06, 0x7f, 0x35,
    0xa7, 0x80, 0xb3, 0xab, 0xf4, 0x5e, 0x2d, 0x8f,
    0x3b, 0x1a, 0x95, 0x07, 0x38, 0xf5, 0x2e, 0x96,
    0x00, 0x74, 0x6a, 0x0e, 0x27, 0xa5, 0x5a, 0x21
};

static const uint8_t rfc_c_key[16] = {
    0xdb, 0xfa, 0xa6, 0x93, 0xd1, 0x76, 0x2c, 0x5b,
    0x66, 0x6a, 0xf5, 0xd9, 0x50, 0x25, 0x8d, 0x01
};

static const uint8_t rfc_c_iv[12] = {
    0x5b, 0xd3, 0xc7, 0x1b, 0x83, 0x6e, 0x0b, 0x76,
    0xbb, 0x73, 0x26, 0x5f
};

static const uint8_t rfc_cfin_payload[36] = {
    0x14, 0x00, 0x00, 0x20, 0xa8, 0xec, 0x43, 0x6d,
    0x67, 0x76, 0x34, 0xae, 0x52, 0x5a, 0xc1, 0xfc,
    0xeb, 0xe1, 0x1a, 0x03, 0x9e, 0xc1, 0x76, 0x94,
    0xfa, 0xc6, 0xe9, 0x85, 0x27, 0xb6, 0x42, 0xf2,
    0xed, 0xd5, 0xce, 0x61
};

static const uint8_t rfc_cfin_record[58] = {
    0x17, 0x03, 0x03, 0x00, 0x35, 0x75, 0xec, 0x4d,
    0xc2, 0x38, 0xcc, 0xe6, 0x0b, 0x29, 0x80, 0x44,
    0xa7, 0x1e, 0x21, 0x9c, 0x56, 0xcc, 0x77, 0xb0,
    0x51, 0x7f, 0xe9, 0xb9, 0x3c, 0x7a, 0x4b, 0xfc,
    0x44, 0xd8, 0x7f, 0x38, 0xf8, 0x03, 0x38, 0xac,
    0x98, 0xfc, 0x46, 0xde, 0xb3, 0x84, 0xbd, 0x1c,
    0xae, 0xac, 0xab, 0x68, 0x67, 0xd7, 0x26, 0xc4,
    0x05, 0x46
};

static int ks_check(const char *name, kem_status_t r, const uint8_t *got, const uint8_t *exp, size_t len){
    if(r != KEM_SUCCESS){
        printf("FAILURE %s: calling\n", name);
        return 1;
    }else if(memcmp(got, exp, len) != 0){
        printf("FAILURE %s: mismatch\n", name);
        return 1;
    }else{
        return 0;
    }
}

static int test_record_init(void){
    record_dir_t d;
    int failures = 0;
    kem_status_t r = record_init(&d, rfc_c_hs);
    failures += ks_check("init key", r, d.key, rfc_c_key, 16);
    failures += ks_check("init iv", r, d.iv, rfc_c_iv, 12);
    if(d.seq != 0) failures++;
    record_clear(&d);
    return failures;
}

static int test_seal_8448(void){
    record_dir_t d;
    int failures = 0;
    kem_status_t r = record_init(&d, rfc_c_hs);
    if(r != KEM_SUCCESS) failures++;
    uint8_t out[128];
    size_t out_len = 0;
    r = record_seal(&d, 22, rfc_cfin_payload, 36, out, sizeof(out), &out_len);
    if(out_len != 58) failures++;
    failures += ks_check("seal 8448", r, out, rfc_cfin_record, 58);
    if(d.seq != 1) failures++;
    record_clear(&d);
    if(failures == 0) printf("[seal-8448] No errors.\n");
    return failures;
}

static int test_open_8448(void){
    record_dir_t d;
    int failures = 0;
    uint8_t out[128];
    size_t out_len = 0;
    uint8_t type = 0;
    kem_status_t r = record_init(&d, rfc_c_hs);
    if(r != KEM_SUCCESS) failures++;
    r = record_open(&d, rfc_cfin_record, 58, out, sizeof(out), &out_len, &type);
    failures += ks_check("open 8448", r, out, rfc_cfin_payload, 36);
    if(out_len != 36) failures++;
    if(type != 22) failures++;
    if(d.seq != 1) failures++;
    record_clear(&d);
    if(failures == 0) printf("[open-8448] No errors\n");
    return failures;
}

static int test_open_tamper(void){
    record_dir_t d;
    int failures = 0;
    uint8_t out[128];
    size_t out_len = 0;
    uint8_t type = 0;
    uint8_t buf[58];
    memcpy(buf, rfc_cfin_record, 58);
    buf[10] ^= 1;
    kem_status_t r = record_init(&d, rfc_c_hs);
    if(r != KEM_SUCCESS) failures++;
    r = record_open(&d, buf, 58, out, sizeof(out), &out_len, &type);
    if(r == KEM_SUCCESS) failures++;
    if(d.seq != 0) failures++;
    record_clear(&d);
    if(failures == 0) printf("[open-tamper] No errors\n");
    return failures;
}

int main(void){
    int number_of_failures = 0;
    number_of_failures += test_record_init();
    number_of_failures += test_seal_8448();
    number_of_failures += test_open_8448();
    number_of_failures += test_open_tamper();

    return number_of_failures;
}
