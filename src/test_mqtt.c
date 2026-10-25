#include "mqtt.h"
#include <stdio.h>
#include <string.h>

struct rl_case{
    size_t len;
    uint8_t exp[4];
    size_t n;
};

static int check(const char *name, const uint8_t *got, size_t got_n, const uint8_t *exp, size_t exp_n){
    if(got_n != exp_n || memcmp(got, exp, exp_n) != 0){
        printf("FAILURE %s :(\n", name);
        return 1;
    }
    else printf("ALL IS FINE %s :)\n", name);
    return 0;
}

int main(void){
    int failures = 0;
    uint8_t expected[] = {0x10,0x10,0x00,0x04,0x4D,0x51,0x54,0x54,0x04,0x02,0x00,0x3C,0x00,0x04,0x44,0x30,0x30,0x31};
    size_t written;
    uint8_t buf[64];
    kem_status_t ret = mqtt_build_connect("D001", 60, buf, sizeof(buf), &written);
    if(ret != KEM_SUCCESS){
        printf("BUILDING WAS UNSUCCESSFUL :(\n");
        failures++;
    }else{
        failures += check("CONNECT D001", buf, written, expected, sizeof(expected));
    }
    printf("%d failures occured\n", failures);
    return failures;
}