#include "transport.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

#define TEST_SIZE 100000
#define PORT 18080
static uint8_t payload[TEST_SIZE];
static uint8_t rcvd[TEST_SIZE];
static uint8_t echoed[TEST_SIZE];

int main(void){
     for(int i = 0; i<TEST_SIZE; i++){
     payload[i] = (uint8_t)(i % 256);
     }
     pid_t pid = fork();
     if(pid<0) return 1;
     if(pid == 0){
          int fd = transport_server_accept(PORT);
          if(fd<0) exit(1);
          transport_recv(fd, rcvd, TEST_SIZE);
          transport_send(fd, rcvd, TEST_SIZE);
          transport_close(fd);
          exit(0);
     }
     sleep(1);
     int fd = transport_client_connect("127.0.0.1", PORT);
     transport_send(fd, payload, TEST_SIZE);
     transport_recv(fd, echoed, TEST_SIZE);
     transport_close(fd);
     waitpid(pid, NULL, 0);
     if(memcmp(payload, echoed, TEST_SIZE) == 0){
          printf("[TRANSPORT] WORKS AS IT WAS INTENDED TO. %d bytes echoed intact :)\n", TEST_SIZE);
          return 0;
     }
     printf("[TRANSPORT] FAILED: There were echo mismatches :(\n");
     return 1;
}
