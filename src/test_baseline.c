#include "baseline.h"
#include "transport.h"
#include "wire.h"
#include "metrics.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>

#define WARMUP 3
#define iterations 30
#define CA_CERT "/thesis/src/certs/ca-cert.pem"
#define SRV_CERT "/thesis/src/certs/server-cert.pem"
#define SRV_KEY "/thesis/src/certs/server-key.pem"

one_baseline(uint16_t port, int iteration){}
