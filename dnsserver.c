#include "socket.c"
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

typedef struct {
  uint16_t transaction_id;
  uint8_t rd : 1;
  uint8_t tc : 1;
  uint8_t aa : 1;
  uint8_t opcode : 4;
  uint8_t qr : 1;
  uint8_t rcode : 4;
  uint8_t z : 3;
  uint8_t ra : 1;
  uint16_t nquestions;
  uint16_t nanswers;
  uint16_t nauthrr;
  uint16_t naddrr;
} dns_header;

typedef struct {
  dns_header *header;
  unsigned char *data;
  unsigned long len;
} dns_request;

typedef struct {
  unsigned char name[2];
  uint16_t type;
  uint16_t class;
  uint16_t rdlength;
  uint32_t ttl;
  unsigned char rdata[4];
} dns_answer;

void header_parse(dns_header *header, void *data) { memcpy(header, data, 12); }

void print_header(dns_header *header) {
  printf("ID: %d\n", header->transaction_id);
  printf("qr: %d\n", header->qr);
  printf("opcode: %d\n", header->opcode);
  printf("aa: %d\n", header->aa);
  printf("tc: %d\n", header->tc);
  printf("rd: %d\n", header->rd);
  printf("ra: %d\n", header->ra);
  printf("z: %d\n", header->z);
  printf("rcode: %d\n", header->rcode);

  printf("qdcount: %d\n", header->nquestions);
  printf("ancount: %d\n", header->nanswers);
  printf("nscount: %d\n", header->nauthrr);
  printf("arcount: %d\n", header->naddrr);
}

void data_parse(dns_request *req, void *data) { req->data = data; }

void print_data(dns_request *req) {
  for (unsigned long i = 0; i < req->len; i++) {
    printf("Data: %x\n", req->data[i]);
  }
}

// Helper to decode "3www6google3com0" -> "www.google.com"
unsigned char *ReadName(unsigned char *reader, unsigned char *buffer,
                        int *count) {
  unsigned char *name;
  unsigned int p = 0, jumped = 0, offset;
  int i, j;

  *count = 1;
  name = (unsigned char *)malloc(256);

  name[0] = '\0';

  // read the names in 3www6google3com format
  while (*reader != 0) {
    if (*reader >= 192) {
      offset = (unsigned int)((*reader) * 256 + *(reader + 1) - 49152);
      reader = buffer + offset - 1;
      jumped = 1;
    } else {
      name[p++] = *reader;
    }

    reader = reader + 1;

    if (jumped == 0) {
      *count = *count + 1;
    }
  }

  name[p] = '\0';
  if (jumped == 1) {
    *count = *count + 1;
  }

  // now convert 3www6google3com0 to www.google.com
  int len = (int)strlen((char *)name);
  for (i = 0; i < len; i++) {
    p = name[i];
    for (j = 0; j < (int)p; j++) {
      name[i] = name[i + 1];
      i = i + 1;
    }
    name[i] = '.';
  }
  name[i - 1] = '\0';
  return name;
}

unsigned char *is_authoritative(char *dns_name_str) {
  FILE *fp = fopen("entries", "r");
  if (fp == NULL) {
    perror("Error opening entries file");
    return NULL;
  }

  char line[256];
  char file_ip[20];

  // entries format: "180.20.56.234   marco.com test.com"

  while (fgets(line, sizeof(line), fp)) {
    char *token = strtok(line, " \t\n");
    if (token == NULL)
      continue;

    strcpy(file_ip, token);

    while ((token = strtok(NULL, " \t\n")) != NULL) {
      if (strcmp(token, dns_name_str) == 0) {
        printf("Found authoritative entry for %s: IP %s\n", dns_name_str,
               file_ip);

        unsigned char *ip_bytes = malloc(4);
        int a, b, c, d;
        if (sscanf(file_ip, "%d.%d.%d.%d", &a, &b, &c, &d) == 4) {
          ip_bytes[0] = (unsigned char)a;
          ip_bytes[1] = (unsigned char)b;
          ip_bytes[2] = (unsigned char)c;
          ip_bytes[3] = (unsigned char)d;
          fclose(fp);
          return ip_bytes;
        }
        free(ip_bytes); // Should not happen if sscanf works, but good practice
      }
    }
  }

  fclose(fp);
  return NULL;
}

int format_entry(unsigned char *input) {
  int length = 0;
  for (int i = 0; i < (int)strlen((char *)input); i++) {
    length++;
  }
  return length + 2;
}

void send_answer(int *fdsocket, struct sockaddr_in *client_addr,
                 unsigned char *ip_res, char *buffer, int stop,
                 dns_request *req, unsigned char *decoded_name) {
  int offset = 0;
  printf("size buffer: %zu\n", sizeof(buffer));
  char *response = malloc(100);
  req->header->nanswers = 0x0100;
  req->header->nauthrr = 0x0100;
  req->header->qr = 1;
  req->header->ra = 1;
  req->header->rcode = 0;
  req->header->z = 0;
  req->header->tc = 0;
  req->header->rd = 0;
  req->header->opcode = 0;
  req->header->aa = 1;
  memcpy(response, req->header, sizeof(*req->header));
  offset += 12;
  memcpy(response + offset, buffer + 12, format_entry(decoded_name) + 4);

  printf("header size is: %d\n", offset);

  dns_answer answer;
  answer.name[0] = 0xC0;
  answer.name[1] = 0x0C;
  answer.type = 0x0100;
  answer.class = 0x0100;
  answer.ttl = 0x3C000000;
  answer.rdlength = 0x0400;
  answer.rdata[0] = ip_res[0];
  answer.rdata[1] = ip_res[1];
  answer.rdata[2] = ip_res[2];
  answer.rdata[3] = ip_res[3];

  printf("answer size is: %zu\n", sizeof(answer));

  offset += format_entry(decoded_name) + 4;
  memcpy(response + offset, &answer,
         6); // copy name, type and class first due to allocation memory
             // mismatch

  offset += 6;

  memcpy(response + offset, &answer.ttl, 4);
  printf("size ttl: %zu\n", sizeof(answer.ttl));

  offset += 4;

  memcpy(response + offset, &answer.rdlength, 2);

  offset += 2;

  memcpy(response + offset, &answer.rdata, 4);

  offset += 4;
  printf("offset is %d\n", offset);
  sendto_socket(fdsocket, response, offset, client_addr, sizeof(*client_addr));

  free(response);
  response = NULL;
}

int main(void) {
  /* Initialize request packet dns */
  dns_request *req = malloc(sizeof(*req));
  req->header = malloc(sizeof(dns_header));

  /* Create the socket */
  int *fdsocket = create_fdsocket();
  /* Create the address */
  struct sockaddr_in *addr = create_addr();
  struct sockaddr_in *client_addr =
      (struct sockaddr_in *)malloc(sizeof(*client_addr));
  /* Bind the socket to the address specified */
  bind_socket(fdsocket, addr);

  socklen_t addrlen = sizeof(*addr);
  char *buffer = (char *)malloc(1024 * sizeof(char));
  ssize_t n;

  while (1) {
    n = readfrom_socket(fdsocket, buffer, 1024, client_addr, &addrlen);
    printf("buffer is: %zu\n", sizeof(buffer));
    char *cached_buffer = malloc(n);
    memcpy(cached_buffer, buffer, n);

    header_parse(req->header, buffer);
    data_parse(req, buffer + 12);
    req->len = (unsigned long)n;
    int stop = 0;
    unsigned char *decoded_name =
        ReadName(req->data, (unsigned char *)buffer, &stop);

    printf("Query for: %s, size: %d\n", decoded_name,
           format_entry(decoded_name));

    unsigned char *ip_res = is_authoritative((char *)decoded_name);
    if (ip_res != NULL) {
      printf("Resolved %s to: %d.%d.%d.%d\n", decoded_name, ip_res[0],
             ip_res[1], ip_res[2], ip_res[3]);
      printf("Size buffer: %ld\n", n);
      send_answer(fdsocket, client_addr, ip_res, cached_buffer, stop, req,
                  decoded_name);

      free(ip_res);
    } else {
      printf("Not authoritative for %s\n", decoded_name);
    }

    free(decoded_name);
  }
  close(*fdsocket);
  free(req);
  free(addr);
  free(client_addr);
  free(buffer);

  return 0;
}