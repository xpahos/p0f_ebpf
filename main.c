/*
 * Copyright © 2019 Yandex LLC.  All rights reserved.
 *
 */

#include <sys/socket.h>
#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <stddef.h>
#include <string.h>

#include "bpf_load.h"
#include "libbpf.h"

#define PARSE_IP_PROG_FD (prog_fd[0])
#define PROG_ARRAY_FD (map_fd[0])

struct p0f {
    uint8_t version;
    uint8_t ittl;
    uint8_t olen;
    uint8_t pclass;
    uint8_t ecn;
    uint8_t flags;
    uint16_t wsize;
    uint8_t bit_fields;
    char opts[40];
};

extern int map_fd[MAX_MAPS];

// Just as example, use map
static uint16_t IDX[10] = {0};

static inline uint8_t map_id(uint16_t port) {
    uint8_t idx = 0;
    int zero_idx = -1;

    for (int i = 0; i < 10; ++i) {
        if (IDX[i] == port) {
            idx = i;
            break;
        }
        if (zero_idx == -1 && IDX[i] == 0) {
            zero_idx = i;
        }
    }

    if (IDX[idx] != port) {
        IDX[zero_idx] = port;
        idx = zero_idx;
    }
    return idx;
}

static inline int set_filter(char *addr, uint16_t port) {
    uint8_t idx = map_id(port);
    printf("Added idx 4: %d\n", idx);

    struct in_addr filter_addr = {0};
    if (inet_pton(AF_INET, addr, &(filter_addr)) < 0) {
        perror("Could not convert addr");
        exit(1);
    }
    int ret = bpf_update_elem(map_fd[1], &filter_addr, &idx, BPF_ANY);
    if (ret != 0)
        return ret;
    return bpf_update_elem(map_fd[3], &idx, &port, BPF_ANY);
}

static inline int set_filter6(char *addr, uint16_t port) {
    uint8_t idx = map_id(port);
    printf("Added idx 6: %d\n", idx);

    struct in6_addr filter_addr = {0};
    if (inet_pton(AF_INET6, addr, &(filter_addr)) < 0) {
        perror("Could not convert addr");
        exit(1);
    }
    int ret = bpf_update_elem(map_fd[2], &filter_addr, &idx, BPF_ANY);
    if (ret != 0)
        return ret;
    return bpf_update_elem(map_fd[3], &idx, &port, BPF_ANY);
}


void print_ipv4() {
    uint32_t value = 0;
    struct in_addr key;
    struct in_addr nxt;
    printf("IPv4:\n");
    while(1) {
        int ret = bpf_get_next_key(map_fd[1], &key, &nxt);
        bpf_lookup_elem(map_fd[1], &key, &value);

        printf("0x%x 0x%x\t", key, value);
        key = nxt;
        if (ret == -1 && errno == ENOENT)
            break;
    }
    printf("\n");
}

void print_ipv6() {
    uint32_t value = 0;
    struct in6_addr key;
    struct in6_addr nxt;
    printf("IPv6:\n");
    while(1) {
        int ret = bpf_get_next_key(map_fd[2], &key, &nxt);
        bpf_lookup_elem(map_fd[2], &key, &value);

        printf("0x%x 0x%x\t", key, value);
        key = nxt;
        if (ret == -1 && errno == ENOENT)
            break;
    }
    printf("\n");
}

void print_ports() {
    uint32_t value = 0;
    uint8_t key = 0;
    uint8_t nxt = 0;
    printf("PORTS:\n");
    while(1) {
        int ret = bpf_get_next_key(map_fd[3], &key, &nxt);
        bpf_lookup_elem(map_fd[3], &key, &value);

        printf("0x%x 0x%x\t", key, value);
        key = nxt;
        if (ret == -1 && errno == ENOENT)
            break;
    }

    printf("\n");
}


int main() {
    char buf[1024];
    char rep[] = "HTTP/1.1 200 Ok\r\nContent-Type: text/html\r\n\r\nOk\r\n\r\n";

    int fd = socket(AF_INET6, SOCK_STREAM , IPPROTO_TCP);
    if (fd < 0) {
        perror("Can't create socket");
        exit(1);
    }

    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &(int){ 1 }, sizeof(int)) < 0) {
        perror("Can't reuse");
        exit(1);
    }

    if (load_bpf_file("bpf_prog.o")) {
        printf("%s", bpf_log_buf);
        exit(1);
    }

    if (set_filter("127.0.0.1", 31337) < 0) {
        perror("Could not set ipv4 filter");
        exit(1);
    }

    if (set_filter6("::1", 31337) < 0) {
        perror("Could not set ipv6 filter");
        exit(1);
    }

    struct sockaddr_in6 sa = {
        .sin6_family = AF_INET6,
        .sin6_addr = in6addr_any,
        .sin6_port = htons(31337),
    };

    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        perror("Can't bind");
        exit(1);
    }

    if (listen(fd, 10) < 0) {
        perror("Can't listen");
        exit(1);
    }

    int64_t tcp_cnt, udp_cnt, icmp_cnt;
    while (1) {
        int lfd = accept(fd, (struct sockaddr*) NULL, NULL);

        read(lfd, buf, 1024);
        write(lfd, rep, sizeof(rep));
        close(lfd);


        print_ipv4();
        print_ipv6();
        print_ports();

        char *faddr = "::1";
        struct in6_addr finaddr = {0};
        inet_pton(AF_INET6, faddr, &finaddr);

        char key[18];
        struct p0f value;

        memcpy(&key, (char *)&finaddr, sizeof(struct in6_addr));
        key[16] = 0x7a;
        key[17] = 0x69;

        if (bpf_lookup_elem(map_fd[4], &key, &value) == 0) {
            printf("Got it\nData:\n\tversion %d\tittl %d\tolen %d\tpclass %d\tecn %d\tflags %x\twsize %d\tbit fields %x\n",
                value.version, value.ittl, value.olen, value.pclass, value.ecn, value.flags, value.wsize, value.bit_fields);
            for (int i = 1; i <= 40; ++i) {
                printf("%02x ", (uint16_t)(value.opts[i-1] & 0xFF));
                if (i % 10 == 0)
                    printf("\n");
            }
            printf("\n");
        }

        for (int i = 0; i < 10; i++) {
            key = IPPROTO_TCP;
            if (bpf_lookup_elem(map_fd, &key, &tcp_cnt) < 0) {
                perror("Lookup tcp failed");
                exit(1);
            }

            key = IPPROTO_UDP;
            if (bpf_lookup_elem(map_fd, &key, &udp_cnt) < 0) {
                perror("Lookup tcp failed");
                exit(1);
            }

            key = IPPROTO_ICMP;
            if (bpf_lookup_elem(map_fd, &key, &icmp_cnt) < 0) {
                perror("Lookup tcp failed");
                exit(1);
            }


            printf("TCP %lld UDP %lld ICMP %lld packets\n", tcp_cnt, udp_cnt, icmp_cnt);
        }
    }
}
