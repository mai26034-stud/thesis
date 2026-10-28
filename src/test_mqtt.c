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

static int expect_fail(const char *name, kem_status_t r){
    if(r == KEM_SUCCESS){
        printf("FAILURE %s\n", name);
        return 1;
    }else{
        printf("ALL IS FINE AND GOOD WITH %s :)\n", name);
        return 0;
    }
}

static int check_value(const char *name, kem_status_t r, unsigned int got, unsigned int exp){
    if(r != KEM_SUCCESS || got != exp){
        printf("FAILURE %s :(\n", name);
        return 1;
    }else{
        printf("ALL IS FINE %s\n", name);
        return 0;
    }
}

int main(void){
    int failures = 0;
    uint8_t expected[] = {0x10,0x10,0x00,0x04,0x4D,0x51,0x54,0x54,0x04,0x02,0x00,0x3C,0x00,0x04,0x44,0x30,0x30,0x31};
    size_t written;
    uint8_t buf[64];
    uint8_t hi[] = {'h', 'i'};
    uint8_t exp_pub0[] = {0x30,0x07,0x00,0x03,0x61,0x2F,0x62,0x68,0x69};
    uint8_t exp_pub1[] = {0x32,0x09,0x00,0x03,0x61,0x2F,0x62,0x00,0x0A,0x68,0x69};
    uint8_t exp_disc[] = {0xE0,0x00};
    uint8_t connack_ok[] = {0x20,0x02,0x00,0x00};
    uint8_t connack_rc5[] = {0x20,0x02,0x00,0x05};
    uint8_t connack_bad[] = {0x30,0x02,0x00,0x00};
    uint8_t puback[] = {0x40,0x02,0x00,0x0A};
    uint8_t out4[4];
    uint8_t rc;
    uint16_t pid;
    size_t n4;
    struct rl_case cases[] = {{0,         {0x00},                   1},
                         {127,       {0x7F},                   1},
                         {128,       {0x80, 0x01},             2},
                         {16383,     {0xFF, 0x7F} ,            2},
                         {16384,      {0x80, 0x80, 0x01},      3},
                         {268435455, {0xFF, 0xFF, 0xFF, 0x7F}, 4}};

    for(size_t i = 0; i < sizeof(cases)/sizeof(cases[0]); i++){
        uint8_t out[4];
        size_t n;
        char name[32];
        snprintf(name, sizeof(name), "RL %zu", cases[i].len);
        kem_status_t r = mqtt_encode_remaining_length(cases[i].len, out, sizeof(out), &n);
        if(r != KEM_SUCCESS){
            printf("Proccess %s unfortunately failed :(\n", name);
            failures++;
        }else{
            failures += check(name, out, n, cases[i].exp, cases[i].n);
        }
    }
    kem_status_t ret = mqtt_build_connect("D001", 60, buf, sizeof(buf), &written);
    if(ret != KEM_SUCCESS){
        printf("BUILDING WAS UNSUCCESSFUL :(\n");
        failures++;
    }else{
        failures += check("CONNECT D001", buf, written, expected, sizeof(expected));
    }
    ret = mqtt_build_publish("a/b", hi, sizeof(hi), 0, 0, buf, sizeof(buf), &written);
    if(ret != KEM_SUCCESS){
        printf("PUBLISHING WAS UNSUCCESSFUL :(\n");
        failures++;
    }else{
        failures += check("PUBLISH qos0", buf, written, exp_pub0, sizeof(exp_pub0));
    }
    ret = mqtt_build_publish("a/b", hi, sizeof(hi), 1, 10, buf, sizeof(buf), &written);
    if(ret != KEM_SUCCESS){
        printf("2nd PUBLISHING WAS UNSUCCESSFUL :(\n");
        failures++;
    }else{
        failures += check("PUBLISH qos1", buf, written, exp_pub1, sizeof(exp_pub1));
    }
    ret = mqtt_build_disconnect(buf, sizeof(buf), &written);
    if(ret != KEM_SUCCESS){
        printf("DISCONNECTING WAS UNSUCCESSFUL :(\n");
        failures++;
    }else{
        failures += check("DISCONNECT", buf, written, exp_disc, sizeof(exp_disc));
    }
    ret = mqtt_parse_connack(connack_ok, sizeof(connack_ok), &rc);
    if(ret != KEM_SUCCESS){
        printf("PARSING OF CONNACK WAS UNSUCCESSFUL :(\n");
        failures++;
    }else{
        failures += check_value("CONNACK rc 0", ret, rc, 0);
    }
    ret = mqtt_parse_connack(connack_rc5, sizeof(connack_rc5), &rc);
    if(ret != KEM_SUCCESS){
        printf("PARSING OF CONNACK WAS UNSUCCESSFUL :(\n");
        failures++;
    }else{
        failures += check_value("CONNACK rc 5", ret, rc, 5);
    }
    ret = mqtt_parse_puback(puback, sizeof(puback), &pid);
    if(ret != KEM_SUCCESS){
        printf("PARSING OF PUBACK WAS UNSUCCESSFUL :(\n");
        failures++;
    }else{
        failures += check_value("PUBACK id 10", ret, pid, 10);
    }
    failures += expect_fail("RL over max", mqtt_encode_remaining_length(268435456, out4, sizeof(out4), &n4));
    failures += expect_fail("CONNECT empty id", mqtt_build_connect("", 60, buf, sizeof(buf), &written));
    failures += expect_fail("CONNECT id 24 chars", mqtt_build_connect("ABCDEFGHIJKLMNOPQRSTUVWX", 60, buf, sizeof(buf), &written));
    failures += expect_fail("CONNECT cap 17", mqtt_build_connect("D001", 60, buf, 17, &written));
    failures += expect_fail("PUBLISH wildcard", mqtt_build_publish("a/+", hi, sizeof(hi), 0, 0, buf, sizeof(buf), &written));
    failures += expect_fail("PUBLISH qos2", mqtt_build_publish("a/b", hi, sizeof(hi), 2, 1, buf, sizeof(buf), &written));
    failures += expect_fail("PUBLISH qos1 id0", mqtt_build_publish("a/b", hi, sizeof(hi), 1, 0, buf, sizeof(buf), &written));
    failures += expect_fail("PUBLISH null payload", mqtt_build_publish("a/b", NULL, 2, 0, 0, buf, sizeof(buf), &written));
    failures += expect_fail("CONNACK bad type", mqtt_parse_connack(connack_bad, sizeof(connack_bad), &rc));
    printf("%d failures occured\n", failures);
    return failures;
}
