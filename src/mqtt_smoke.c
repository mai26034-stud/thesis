#include "mqtt.h"
#include "transport.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

int main(void){
    int fd = transport_client_connect("127.0.0.1", 1883);
    if(fd < 0){
        printf("fd failed..\n");
        return 1;
    }
    uint8_t buf[256];
    size_t n;
    uint8_t rc = 0;
    uint16_t pid = 0;
    kem_status_t r = mqtt_build_connect("D001-pub", 60, buf, sizeof(buf), &n);
    if(r != KEM_SUCCESS){
        printf("building a connection has regretably failed..\n");
        transport_close(fd);
        return 1;
    }
    r = transport_send(fd, buf, n);
    if(r != KEM_SUCCESS){
        printf("sending was unsuccessful..\n");
        transport_close(fd);
        return 1;
    }
    uint8_t resp[4];
    r = transport_recv(fd, resp, 4);
    if(r != KEM_SUCCESS){
        printf("recieving failed..\n");
        transport_close(fd);
        return 1;
    }
    r = mqtt_parse_connack(resp, 4, &rc);
    if(r != KEM_SUCCESS){
        printf("parse connack failed..\n");
        transport_close(fd);
        return 1;
    }
    if(rc != 0){
        printf("%d failed..\n", rc);
        transport_close(fd);
        return 1;
    }
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    uint64_t ms = (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
    char payload[128];
    int plen = snprintf(payload, sizeof(payload), "{\"e\":[{\"v\":%.1f}],\"tmstp\":%llu}", 23.4, (unsigned long long)ms);
    if(plen <= 0 || (size_t)plen >= sizeof(payload)){
        printf("%s payload was no good...\n", payload);
        transport_close(fd);
        return 1;
    }
    r = mqtt_build_publish("tele/D001/3303/0/5700", (const uint8_t *)payload, (size_t)plen, 1, 1, buf, sizeof(buf), &n);
    if(r != KEM_SUCCESS){
        printf("publishing failed to build :(\n");
        transport_close(fd);
        return 1;
    }
    r = transport_send(fd, buf, n);
    if(r != KEM_SUCCESS){
        printf("sending failed...\n");
        transport_close(fd);
        return 1;
    }
    r = transport_recv(fd, resp, 4);
    if(r != KEM_SUCCESS){
        printf("recieving failed...\n");
        transport_close(fd);
        return 1;
    }
    r = mqtt_parse_puback(resp, 4, &pid);
    if(r != KEM_SUCCESS || pid != 1){
        printf("pid was %d\n", pid);
        transport_close(fd);
        return 1;
    }
    r = mqtt_build_disconnect(buf, sizeof(buf), &n);
    if(r != KEM_SUCCESS){
        printf("disconecting failed...\n");
        transport_close(fd);
        return 1;
    }
    r = transport_send(fd, buf, n);
    if(r != KEM_SUCCESS){
        printf("sending failed...\n");
        transport_close(fd);
        return 1;
    }
    transport_close(fd);
    printf("ALL IS OK...\n");
    return 0;
}
