#include "transcript.h"
#include "keyschedule.h"
#include "kem.h"
#include <stdio.h>
#include <string.h>

static int test_transcript_on_determinism(void);
static int test_transcript_on_sensitivity(void);
static int test_transcript_on_cumulativity(void);
static int test_ks_deterministic(void);
static int test_ks_sensitive(void);

int main(void){
    int number_of_failures = 0;
    number_of_failures += test_transcript_on_determinism();
    number_of_failures += test_transcript_on_sensitivity();
    number_of_failures += test_transcript_on_cumulativity();
    number_of_failures += test_ks_deterministic();
    number_of_failures += test_ks_sensitive();

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