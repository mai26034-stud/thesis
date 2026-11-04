#include "transcript.h"
#include "keyschedule.h"
#include "kem.h"
#include <stdio.h>
#include <string.h>

static const uint8_t rfc_early[32] = {
    0x33, 0xad, 0x0a, 0x1c, 0x60, 0x7e, 0xc0, 0x3b,
    0x09, 0xe6, 0xcd, 0x98, 0x93, 0x68, 0x0c, 0xe2,
    0x10, 0xad, 0xf3, 0x00, 0xaa, 0x1f, 0x26, 0x60,
    0xe1, 0xb2, 0x2e, 0x10, 0xf1, 0x70, 0xf9, 0x2a
};

static const uint8_t rfc_des[32] = {
    0x6f, 0x26, 0x15, 0xa1, 0x08, 0xc7, 0x02, 0xc5,
    0x67, 0x8f, 0x54, 0xfc, 0x9d, 0xba, 0xb6, 0x97,
    0x16, 0xc0, 0x76, 0x18, 0x9c, 0x48, 0x25, 0x0c,
    0xeb, 0xea, 0xc3, 0x57, 0x6c, 0x36, 0x11, 0xba
};

static const uint8_t rfc_ikm[32] = {
    0x8b, 0xd4, 0x05, 0x4f, 0xb5, 0x5b, 0x9d, 0x63,
    0xfd, 0xfb, 0xac, 0xf9, 0xf0, 0x4b, 0x9f, 0x0d,
    0x35, 0xe6, 0xd6, 0x3f, 0x53, 0x75, 0x63, 0xef,
    0xd4, 0x62, 0x72, 0x90, 0x0f, 0x89, 0x49, 0x2d
};

static const uint8_t rfc_hs[32] = {
    0x1d, 0xc8, 0x26, 0xe9, 0x36, 0x06, 0xaa, 0x6f,
    0xdc, 0x0a, 0xad, 0xc1, 0x2f, 0x74, 0x1b, 0x01,
    0x04, 0x6a, 0xa6, 0xb9, 0x9f, 0x69, 0x1e, 0xd2,
    0x21, 0xa9, 0xf0, 0xca, 0x04, 0x3f, 0xbe, 0xac
};

static const uint8_t rfc_th_sh[32] = {
    0x86, 0x0c, 0x06, 0xed, 0xc0, 0x78, 0x58, 0xee,
    0x8e, 0x78, 0xf0, 0xe7, 0x42, 0x8c, 0x58, 0xed,
    0xd6, 0xb4, 0x3f, 0x2c, 0xa3, 0xe6, 0xe9, 0x5f,
    0x02, 0xed, 0x06, 0x3c, 0xf0, 0xe1, 0xca, 0xd8
};

static const uint8_t rfc_c_hs[32] = {
    0xb3, 0xed, 0xdb, 0x12, 0x6e, 0x06, 0x7f, 0x35,
    0xa7, 0x80, 0xb3, 0xab, 0xf4, 0x5e, 0x2d, 0x8f,
    0x3b, 0x1a, 0x95, 0x07, 0x38, 0xf5, 0x2e, 0x96,
    0x00, 0x74, 0x6a, 0x0e, 0x27, 0xa5, 0x5a, 0x21
};

static const uint8_t rfc_s_hs[32] = {
    0xb6, 0x7b, 0x7d, 0x69, 0x0c, 0xc1, 0x6c, 0x4e,
    0x75, 0xe5, 0x42, 0x13, 0xcb, 0x2d, 0x37, 0xb4,
    0xe9, 0xc9, 0x12, 0xbc, 0xde, 0xd9, 0x10, 0x5d,
    0x42, 0xbe, 0xfd, 0x59, 0xd3, 0x91, 0xad, 0x38
};

static const uint8_t rfc_dhs[32] = {
    0x43, 0xde, 0x77, 0xe0, 0xc7, 0x77, 0x13, 0x85,
    0x9a, 0x94, 0x4d, 0xb9, 0xdb, 0x25, 0x90, 0xb5,
    0x31, 0x90, 0xa6, 0x5b, 0x3e, 0xe2, 0xe4, 0xf1,
    0x2d, 0xd7, 0xa0, 0xbb, 0x7c, 0xe2, 0x54, 0xb4
};

static const uint8_t rfc_ms[32] = {
    0x18, 0xdf, 0x06, 0x84, 0x3d, 0x13, 0xa0, 0x8b,
    0xf2, 0xa4, 0x49, 0x84, 0x4c, 0x5f, 0x8a, 0x47,
    0x80, 0x01, 0xbc, 0x4d, 0x4c, 0x62, 0x79, 0x84,
    0xd5, 0xa4, 0x1d, 0xa8, 0xd0, 0x40, 0x29, 0x19
};

static const uint8_t rfc_s_key[16] = {
    0x3f, 0xce, 0x51, 0x60, 0x09, 0xc2, 0x17, 0x27,
    0xd0, 0xf2, 0xe4, 0xe8, 0x6e, 0xe4, 0x03, 0xbc
};

static const uint8_t rfc_s_iv[12] = {
    0x5d, 0x31, 0x3e, 0xb2, 0x67, 0x12, 0x76, 0xee,
    0x13, 0x00, 0x0b, 0x30
};

static const uint8_t rfc_s_fin[32] = {
    0x00, 0x8d, 0x3b, 0x66, 0xf8, 0x16, 0xea, 0x55,
    0x9f, 0x96, 0xb5, 0x37, 0xe8, 0x85, 0xc3, 0x1f,
    0xc0, 0x68, 0xbf, 0x49, 0x2c, 0x65, 0x2f, 0x01,
    0xf2, 0x88, 0xa1, 0xd8, 0xcd, 0xc1, 0x9f, 0xc8
};

static int test_transcript_on_determinism(void);
static int test_transcript_on_sensitivity(void);
static int test_transcript_on_cumulativity(void);
static int test_ks_deterministic(void);
static int test_ks_sensitive(void);
static int test_rfc8448(void);
static int test_stage_8448(void);
static int test_stage_chain(void);

int main(void){
    int number_of_failures = 0;
    number_of_failures += test_transcript_on_determinism();
    number_of_failures += test_transcript_on_sensitivity();
    number_of_failures += test_transcript_on_cumulativity();
    number_of_failures += test_ks_deterministic();
    number_of_failures += test_ks_sensitive();
    number_of_failures += test_rfc8448();
    number_of_failures += test_stage_8448();
    number_of_failures += test_stage_chain();
    
    return number_of_failures;
}

static int test_transcript_on_determinism(){
    transcript_t t1;
    transcript_t t2;
    uint8_t h1[32];
    uint8_t h2[32];

    const uint8_t msg[] = "hello";
    size_t msg_len = 5;
    transcript_init(&t1);
    transcript_init(&t2);
    
    transcript_append(&t1, msg, msg_len);
    transcript_append(&t2, msg, msg_len);

    transcript_get_hash(&t1, h1);
    transcript_get_hash(&t2, h2);

    if(memcmp(h1, h2, 32) == 0){
         printf("ALL IS FINE AND OK!! :))\n");
         return 0;
    }
    else{
        printf("An error did unfortunately occur :(");
        return 1;
    }
}

static int test_transcript_on_sensitivity(){
    transcript_t t1;
    transcript_t t2;
    uint8_t h1[32];
    uint8_t h2[32];

    const uint8_t msg[] = "hello";
    const uint8_t msg2[] = "hellp";
    size_t msg_len = 5;
    transcript_init(&t1);
    transcript_init(&t2);
    
    transcript_append(&t1, msg, msg_len);
    transcript_append(&t2, msg2, msg_len);

    transcript_get_hash(&t1, h1);
    transcript_get_hash(&t2, h2);

    if(memcmp(h1, h2, 32) != 0){
         printf("ALL IS FINE AND OK!! :))\n");
         return 0;
    }
    else{
        printf("An error did unfortunately occur :(");
        return 1;
    }
}

static int test_transcript_on_cumulativity(){
    transcript_t t1;
    transcript_t t2;
    uint8_t h1[32];
    uint8_t h2[32];

    const uint8_t msg[] = "foo";
    const uint8_t msg2[] = "bar";
    const uint8_t msg3[] = "foobar";
    size_t msg_len = 3;
    size_t msg2_len = 3;
    size_t msg3_len = 6;
    transcript_init(&t1);
    transcript_init(&t2);
    
    transcript_append(&t1, msg, msg_len);
    transcript_append(&t1, msg2, msg2_len);
    transcript_append(&t2, msg3, msg3_len);

    transcript_get_hash(&t1, h1);
    transcript_get_hash(&t2, h2);

    if(memcmp(h1, h2, 32) == 0){
         printf("ALL IS FINE AND OK!! :))\n");
         return 0;
    }
    else{
        printf("An error did unfortunately occur :(");
        return 1;
    }
}

static int test_ks_deterministic(){
    uint8_t ss_eph[32];
    uint8_t ss_auth[32];
    memset(ss_eph, 0xAA, 32);
    memset(ss_auth, 0xBB, 32);
    uint8_t ms1[32];
    uint8_t ms2[32];
    derive_handshake_secrets(ss_eph, 32, ss_auth, 32, ms1);
    derive_handshake_secrets(ss_eph, 32, ss_auth, 32, ms2);
    if(memcmp(ms1, ms2, 32) == 0) return 0;
    else return 1;
}

static int test_ks_sensitive(){
    uint8_t ss_eph[32];
    uint8_t ss_auth[32];
    memset(ss_eph, 0xAA, 32);
    memset(ss_auth, 0xBB, 32);
    uint8_t ms1[32];
    uint8_t ms2[32];
    derive_handshake_secrets(ss_eph, 32, ss_auth, 32, ms1);
    ss_auth[0] ^= 1;
    derive_handshake_secrets(ss_eph, 32, ss_auth, 32, ms2);
    if(memcmp(ms1, ms2, 32) != 0){
        printf("[ks-sens] is OK\n");
        return 0;
    }
    else{
        printf("[ks-sen] test was unsuccessful :(");
        return 1;
    }
}

static int ks_check(const char *name, kem_status_t r, const uint8_t *got, const uint8_t *exp, size_t len){
    if(r != KEM_SUCCESS){
        printf("FAILURE %s: calling was unfortunately unsuccessful..", name);
        return 1;
    }else if(memcmp(got, exp, len) != 0){
        printf("FAILURE %s: A mismatch occured...", name);
        return 1;
    }else{
        return 0;
    }
}

static int test_rfc8448(void){
    int failures = 0;
    uint8_t es[32];
    uint8_t zeros[32] = {0};
    uint8_t th_empty[32], d[32], hs[32], c[32], s[32], dh[32], ms[32], fin[32];
    uint8_t key[16];
    uint8_t iv[12];
    transcript_t te;
    kem_status_t r = ks_extract(zeros, 32, zeros, 32, es);
    failures += ks_check("1 early secret",r, es, rfc_early, 32);
    transcript_init(&te);
    r = transcript_get_hash(&te, th_empty);
    if(r != KEM_SUCCESS) failures++;
    r = ks_derive_secret(es, "derived", th_empty, d);
    failures += ks_check("2 derived(early)", r, d, rfc_des, 32);
    r = ks_extract(d, 32, rfc_ikm, 32, hs);
    failures += ks_check("3 handshake secret", r, hs, rfc_hs, 32);
    r = ks_derive_secret(hs, "c hs traffic", rfc_th_sh, c);
    failures += ks_check("4 c hs traffic", r, c, rfc_c_hs, 32);
    r = ks_derive_secret(hs, "s hs traffic", rfc_th_sh, s);
    failures += ks_check("5 s hs traffic", r, s, rfc_s_hs, 32);
    r = ks_derive_secret(hs, "derived", th_empty, dh);
    failures += ks_check("6 derived(hs)", r, dh, rfc_dhs,32);
    r = ks_extract(dh, 32, zeros, 32, ms);
    failures += ks_check("7 master secret", r, ms, rfc_ms, 32);
    r = ks_traffic_keys(s, key, iv);
    failures += ks_check("8 server key", r, key, rfc_s_key, 16);
    failures += ks_check("8 server iv", r, iv, rfc_s_iv, 12);
    r = ks_expand_label(s, "finished", NULL, 0, fin, 32);
    failures += ks_check("9 server finished key", r, fin, rfc_s_fin, 32);
    if(failures == 0) printf("[RFC 8448] key schedule is OK\n");
    return failures;
}

static int test_stage_8448(void){
    ks_state_t st;
    kem_status_t r = ks_stage_handshake(&st, rfc_ikm, 32);
    int failures = ks_check("stage handshake", r, st.hs, rfc_hs, 32);
    ks_state_clear(&st);
    if(failures == 0) printf("[stage handshake] RFC 8448 was OK :)\n");
    return failures;
}

static int test_stage_chain(void){
    ks_state_t st;
    uint8_t eph[32], auth[32];
    uint8_t zeros[32] = {0};
    uint8_t th0[32];
    uint8_t th_empty[32], d[32], hs[32], c[32], s[32], dh[32], ms[32], fin[32];
    int failures = 0;
    transcript_t te;
    transcript_init(&te);
    kem_status_t r = transcript_get_hash(&te, th0);
    memset(eph, 0xAA, 32);
    memset(auth, 0xBB, 32);
    r = ks_stage_handshake(&st, eph, 32);
    if(r != KEM_SUCCESS) return 1;
    r = ks_stage_auth(&st, auth, 32);
    if(r != KEM_SUCCESS) return 1;
    
}
