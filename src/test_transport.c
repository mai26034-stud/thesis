#include "transport.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

#define TEST_SIZE 100000
static uint8_t payload[TEST_SIZE];
static uint8_t rcvd[TEST_SIZE];

int transport_testing(void);

int transport_testing(void){
     for(int i = 0; i<TEST_SIZE; i++){
     payload[i] = (uint8_t)(i % 256);
     }
     pid_t pid = fork();
     if(pid<0) return 1;
     else{
          int fd = transport_server_accept(18080);
          if(fd<0) exit(1);
          transport_recv(fd, rcvd, TEST_SIZE);
          transport_send(fd, rcvd, TEST_SIZE);
          transport_close(fd);
          exit(0);
     }
     sleep(1);
     int fd = transport_client_connect("127.0.0.1", PORT);
     transport_send(fd, payload, TEST_SIZE);
     transport_recv(fd, payload, TEST_SIZE);
     if(memcmp(payload, rcvd) != 0) exit(1);
     else{
          close();
          waitpid();
     }
}
