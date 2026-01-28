#include <netinet/in.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#define PORT 1085

int *create_fdsocket() {
  int *sockfd = (int *)malloc(sizeof(int));
  *sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  if (*sockfd == -1) {
    fprintf(stderr, "Error creating socket\n");
    return NULL;
  } else {
    printf("Socket created successfully\n");
    return sockfd;
  }
}

struct sockaddr_in *create_addr() {
  struct sockaddr_in *addr =
      (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));
  addr->sin_family = AF_INET;
  addr->sin_port = htons(PORT);
  addr->sin_addr.s_addr = INADDR_ANY;
  return addr;
}

void bind_socket(int *fdsocket, struct sockaddr_in *addr) {
  if (bind(*fdsocket, (struct sockaddr *)addr, sizeof(*addr)) < 0) {
    fprintf(stderr, "Error binding socket\n");
    exit(-1);
  }
  printf("Socket bound successfully\n");
}

ssize_t readfrom_socket(int *fdsocket, char *buffer, size_t len,
                        struct sockaddr_in *client_addr, socklen_t *addrlen) {
  ssize_t n = recvfrom(*fdsocket, buffer, len, MSG_WAITALL,
                       (struct sockaddr *)client_addr, addrlen);
  buffer[n] = '\0';
  if (n < 0) {
    fprintf(stderr, "Error receiving data\n");
    exit(1);
  }
  return n;
}

void sendto_socket(int *fdsocket, char *buffer, size_t len,
                   struct sockaddr_in *client_addr, socklen_t addrlen) {
  if (sendto(*fdsocket, buffer, len, MSG_CONFIRM,
             (struct sockaddr *)client_addr, addrlen) < 0) {
    fprintf(stderr, "Error sending data\n");
    exit(1);
  }
}
