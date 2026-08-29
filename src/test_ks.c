#include "transcript.h"
#include "keyschedule.h"
#include "kem.h"
#include <stdio.h>
#include <string.h>

static int test_transcript_on_determinism(void);
static int test_transcript_on_sensitivity(void);
static int test_transcript_on_cumulativity(void);

int main(void){
    int number_of_failures = 0;
    number_of_failures += test_transcript_on_determinism();
    number_of_failures += test_transcript_on_sensitivity();
    number_of_failures += test_transcript_on_cumulativity();

    return number_of_failures;
}

static int test_transcript_on_determinism(){
    transcript_t t1;
    transcript_t t2;
    uint8_t h1[32];
    uint8_t h2[32];

    const uint8_t msg[] = "hello";
    size_t msg_len = 5;
    transcript_init(h1);
    transcript_init(h2);
    
    transcript_append(h1, msg);
    transcript_append(h2, msg);

    transcript_get_hash(&t1, h1);
    transcript_get_hash(&t2, h2);

    if(memcmp(h1, h2, 32) == 0) printf("ALL IS FINE AND OK!! :))\n"); return 0;
    else print 1;
}