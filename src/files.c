#include "files.h"
#include <fcntl.h>
#include <unistd>

kem_status_t file_write(const char *path, const uint8_t *buf, size_t len){
  if(path == NULL)
}
