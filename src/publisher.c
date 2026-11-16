#include "handshake.h"
#include "channel.h"
#include "transport.h"
#include "files.h"
#include "metrics.h"
#include "mqtt.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>

#define CLIENT_ID "D001"
#define TOPIC "tele/D001/3303/0/5700"

static int parse_num(){}
