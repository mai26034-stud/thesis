#include "files.h"
#include <fcntl.h>
#include <unistd.h>

kem_status_t file_write(const char *path, const uint8_t *buf, size_t len){
  if(path == NULL || (buf == NULL && len > 0)) return KEM_ERROR;
  int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
  if(fd < 0) return KEM_ERROR;
  size_t done = 0;
  while(done < len){
    ssize_t n = write(fd, buf + done, len - done);
    if(n <= 0){
      close(fd);
      return KEM_ERROR;
    }
    done += (size_t)n;
  }
  if(close(fd) != 0) return KEM_ERROR;
  return KEM_SUCCESS;
}

kem_status_t file_read(const char *path, uint8_t *buf, size_t cap, size_t *len_out){
  if(path == NULL || buf == NULL || len_out == NULL) return KEM_ERROR;
  int fd = open(path, O_RDONLY);
  if(fd < 0) return KEM_ERROR;
  size_t done = 0;
  while(done < cap){
    ssize_t n = read(fd, buf + done, cap - done);
    if(n < 0){
      close(fd);
      return KEM_ERROR;
    }
    if(n == 0) break;
    done += (size_t)n;
  }
  uint8_t extra;
  ssize_t more = (done == cap) ? read(fd, &extra, 1) : 0;
  close(fd);
  if(more != 0) return KEM_ERROR;
  *len_out = done;
  return KEM_SUCCESS;
}