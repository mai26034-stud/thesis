#include "mqtt.h"
#include "transport.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

int main(void){
    int fd = transport_client_connect("127.0.0.1", 1883);
    if(fd < 0){
        printf("[mqtt_smoke] FAIL: connect.\n");
        return 1;
    }
    uint8_t buf[256];
    size_t n;
    uint8_t rc = 0;
    uint16_t pid = 0;
    kem_status_t r = mqtt_build_connect("D001-pub", 60, buf, sizeof(buf), &n);
    if(r != KEM_SUCCESS){
        printf("[mqtt_smoke] FAIL: build CONNECT.\n");
        transport_close(fd);
        return 1;
    }
    r = transport_send(fd, buf, n);
    if(r != KEM_SUCCESS){
        printf("[mqtt_smoke] FAIL: send CONNECT.\n");
        transport_close(fd);
        return 1;
    }
    uint8_t resp[4];
    r = transport_recv(fd, resp, 4);
    if(r != KEM_SUCCESS){
        printf("[mqtt_smoke] FAIL: receive CONNACK.\n");
        transport_close(fd);
        return 1;
    }
    r = mqtt_parse_connack(resp, 4, &rc);
    if(r != KEM_SUCCESS){
        printf("[mqtt_smoke] FAIL: parse CONNACK.\n");
        transport_close(fd);
        return 1;
    }
    if(rc != 0){
        printf("[mqtt_smoke] FAIL: CONNACK return code.%d\n", rc);
        transport_close(fd);
        return 1;
    }
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    uint64_t ms = (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
    char payload[128];
    int plen = snprintf(payload, sizeof(payload), "{\"e\":[{\"v\":%.1f}],\"tmstp\":%llu}", 23.4, (unsigned long long)ms);
    if(plen <= 0 || (size_t)plen >= sizeof(payload)){
        printf("[mqtt_smoke] FAIL: payload formatting.\n");
        transport_close(fd);
        return 1;
    }
    r = mqtt_build_publish("tele/D001/3303/0/5700", (const uint8_t *)payload, (size_t)plen, 1, 1, buf, sizeof(buf), &n);
    if(r != KEM_SUCCESS){
        printf("[mqtt_smoke] FAIL: build PUBLISH.\n");
        transport_close(fd);
        return 1;
    }
    r = transport_send(fd, buf, n);
    if(r != KEM_SUCCESS){
        printf("[mqtt_smoke] FAIL: send PUBLISH.\n");
        transport_close(fd);
        return 1;
    }
    r = transport_recv(fd, resp, 4);
    if(r != KEM_SUCCESS){
        printf("[mqtt_smoke] FAIL: receive PUBACK.\n");
        transport_close(fd);
        return 1;
    }
    r = mqtt_parse_puback(resp, 4, &pid);
    if(r != KEM_SUCCESS || pid != 1){
        printf("[mqtt_smoke] FAIL: PUBACK packet id %d\n", pid);
        transport_close(fd);
        return 1;
    }
    r = mqtt_build_disconnect(buf, sizeof(buf), &n);
    if(r != KEM_SUCCESS){
        printf("[mqtt_smoke] FAIL: build DISCONNECT.\n");
        transport_close(fd);
        return 1;
    }
    r = transport_send(fd, buf, n);
    if(r != KEM_SUCCESS){
        printf("[mqtt_smoke] FAIL: send DISCONNECT.\n");
        transport_close(fd);
        return 1;
    }
    transport_close(fd);
    printf("[mqtt_smoke] OK.\n");
    return 0;
}
