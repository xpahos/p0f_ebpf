/*
 * Copyright © 2019 Yandex LLC.  All rights reserved.
 *
 */

#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <uapi/linux/bpf.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/ipv6.h>
#include <uapi/linux/if_ether.h>
#include "bpf_helpers.h"

#define KBUILD_MODNAME "bpf_prog"
#include <net/tcp.h>
#define PROG(F) SEC("inner_prog/"__stringify(F)) int bpf_func_##F

struct p0f {
    u8 version;
    u8 ittl;
    u8 olen;
    u8 pclass;
    u8 ecn;
    u8 flags;
    u16 wsize;
    u8 bit_fields;
    char opts[40];
};

struct bpf_map_def SEC("maps") jmp_table = {
    .type = BPF_MAP_TYPE_PROG_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 8,
};

struct bpf_map_def SEC("maps") in_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct in_addr),
    .value_size = sizeof(u8),
    .max_entries = 10,
};

struct bpf_map_def SEC("maps") in6_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct in6_addr),
    .value_size = sizeof(u8),
    .max_entries = 10,
};

struct bpf_map_def SEC("maps") ports_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u8),
    .value_size = sizeof(u16),
    .max_entries = 10,
};

struct bpf_map_def SEC("maps") p0f_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct in6_addr) + sizeof(u16),
    .value_size = sizeof(struct p0f),
    .max_entries = 100,
};

#define IP_ID_SET 0x01
#define IP_FLOW_SET 0x02
#define TCP_SEQ_ZERO 0x04
#define TCP_ACK_NOTZERO_NOTSET 0x08
#define TCP_ACK_ZERO_SET 0x16
#define TCP_URG_NOTZERO_NOTSET 0x32
#define TCP_URG_SET 0x64
#define TCP_PUSH 0x128

#define IPV4_PARSER 1
#define IPV6_PARSER 2

#define MAGIC_RETURN return 0;

struct bpf_context {
    unsigned long long pad;
    void *skbaddr;
    unsigned int len;
};

static inline void copy_ipv4(char *dst, char *src) {
    dst[0] = 0;
    dst[1] = 0;
    dst[2] = 0;
    dst[3] = 0;
    dst[4] = 0;
    dst[5] = 0;
    dst[6] = 0;
    dst[7] = 0;
    dst[8] = 0;
    dst[9] = 0;
    dst[10] = 0;
    dst[11] = 0;
    dst[12] = src[0];
    dst[13] = src[1];
    dst[14] = src[2];
    dst[15] = src[3];

}

static inline void copy_ipv6(char *dst, char *src) {
    dst[0] = src[0];
    dst[1] = src[1];
    dst[2] = src[2];
    dst[3] = src[3];
    dst[4] = src[4];
    dst[5] = src[5];
    dst[6] = src[6];
    dst[7] = src[7];
    dst[8] = src[8];
    dst[9] = src[9];
    dst[10] = src[10];
    dst[11] = src[11];
    dst[12] = src[12];
    dst[13] = src[13];
    dst[14] = src[14];
    dst[15] = src[15];
}


SEC("tracepoint/net/netif_receive_skb")
int bpf_prog(struct bpf_context *ctx) {
    struct sk_buff *skb = (struct sk_buff*)ctx->skbaddr;

    char *head;
    u16 mac_header;
    u16 net_header;
    u16 tcp_header;

    bpf_probe_read(&head, sizeof(head), ((char*)skb) + offsetof(typeof(*skb), head));

    bpf_probe_read(&mac_header, sizeof(mac_header), ((char*)skb) + offsetof(typeof(*skb), mac_header));
    bpf_probe_read(&net_header, sizeof(net_header), ((char*)skb) + offsetof(typeof(*skb), network_header));
    bpf_probe_read(&tcp_header, sizeof(tcp_header), ((char*)skb) + offsetof(typeof(*skb), transport_header));

    u64 mac_proto = 0;

    struct ethhdr ethh = {0};
    bpf_probe_read(&ethh, sizeof(ethh), ((char*)head) + mac_header);
    mac_proto = ntohs(ethh.h_proto);

    u64 ip_proto = 0;

    struct p0f p = {0};

    char hash[18] = {0};
    u8 *port_idx_ptr = NULL;
    u8 port_idx = 0;
    u8 bit_fields = 0;
    u16 payload_size = 0;
    switch (mac_proto) {
        case ETH_P_IP: {
            p.version = 4;

            struct iphdr iph = {0};
            bpf_probe_read(&iph, sizeof(iph), ((char*)head) + net_header);

            port_idx_ptr = bpf_map_lookup_elem(&in_map, &iph.daddr);
            ip_proto = iph.protocol;
            p.ittl = iph.ttl;
            p.olen = (iph.ihl - 5) * 4; // x * 32(one word) / 8
            p.ecn = 1 << (iph.tos & INET_ECN_MASK);
            if (iph.id != 0) {
                bit_fields ^= IP_ID_SET;
            }
            p.flags = ntohs(iph.frag_off) & ~IP_OFFSET;
            payload_size = ntohs(iph.tot_len);
            copy_ipv4(hash, (char *)&iph.saddr);

            break;
        }
        case ETH_P_IPV6: {
            p.version = 6;

            struct ipv6hdr iph = {0};
            bpf_probe_read(&iph, sizeof(iph), ((char*)head) + net_header);

            port_idx_ptr = bpf_map_lookup_elem(&in6_map, &iph.daddr);
            ip_proto = iph.nexthdr;
            p.ittl = iph.hop_limit;
            p.olen = 0; // right now we don't iterate through headers
            p.ecn = 0;
            p.flags = 0;
            if (iph.flow_lbl != 0) {
                bit_fields ^= IP_FLOW_SET;
            }
            payload_size = ntohs(iph.payload_len);
            copy_ipv6(hash, (char *)&iph.saddr);

            break;
        }
    }
    if (!port_idx_ptr)
        MAGIC_RETURN

    port_idx = *port_idx_ptr;

    if (ip_proto != IPPROTO_TCP)
        MAGIC_RETURN

    struct tcphdr tcph = {0};
    bpf_probe_read(&tcph, sizeof(tcph), ((char*)head) + tcp_header);

    u16 *port = bpf_map_lookup_elem(&ports_map, &port_idx);

    if (!port)
        MAGIC_RETURN

    if (*port != ntohs(tcph.dest))
        MAGIC_RETURN

    if (!tcph.syn)
        MAGIC_RETURN

    // copy in reverse order
    hash[16] = *((u8*)port+1);
    hash[17] = *((u8*)port);

    u8 opts_size = (tcph.doff * 4) - sizeof(struct tcphdr);
    bpf_probe_read(&p.opts, sizeof(p.opts), ((char*)head) + tcp_header + sizeof(struct tcphdr));

    if (tcph.seq == 0) {
        bit_fields ^= TCP_SEQ_ZERO;
    }

    if (tcph.ack_seq != 0 && tcph.ack == 0) {
        bit_fields ^= TCP_ACK_NOTZERO_NOTSET;
    }

    if (tcph.ack_seq == 0 && tcph.ack == 1) {
        bit_fields ^= TCP_ACK_ZERO_SET;
    }

    if (tcph.urg_ptr != 0 && tcph.urg != 0) {
        bit_fields ^= TCP_URG_NOTZERO_NOTSET;
    }

    if (tcph.urg == 1) {
        bit_fields ^= TCP_URG_SET;
    }

    if (tcph.psh == 1) {
        bit_fields ^= TCP_PUSH;
    }

    p.wsize = tcph.window;
    p.pclass = payload_size - sizeof(struct tcphdr) - opts_size;
    p.bit_fields = bit_fields;

    char fmt[] = "FIELDS %x %x %x\n";
    bpf_trace_printk(fmt, sizeof(fmt), hash[15], hash[16], hash[17]);
    bpf_map_update_elem(&p0f_map, &hash, &p, BPF_ANY);

    MAGIC_RETURN
}

char _license[] SEC("license") = "GPL";
