//go:build ignore

#include <linux/bpf.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <netinet/in.h>

#define ETHER_HDR_LEN sizeof(struct ethhdr)
#define IP_HDR_LEN sizeof(struct iphdr)
#define TCP_HDR_LEN sizeof(struct tcphdr)

// TLS record types
#define TLS_HANDSHAKE 0x16
#define TLS_CLIENT_HELLO 0x01
#define SNI_EXTENSION 0

struct server_name {
   char server_name[256];
};

struct extension {
   __u16 type;
   __u16 len;
} __attribute__((packed));

struct sni_extension {
   __u16 list_len;
   __u8 type;
   __u16 len;
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY); 
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} pkt_count SEC(".maps"); 

// Compare two strings
static inline int bpf_strcmp(const char *str1, const char *str2, int len) {
    for (int i = 0; i < len; i++) {
        if (str1[i] != str2[i]) {
            return 1; // Strings are different
        }
    }
    return 0; // Strings are equal
}

SEC("xdp") 
int filter_sni(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // Check packet length
    if (data + ETHER_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN > data_end)
        return XDP_PASS;

    // Get pointers to Ethernet, IP, and TCP headers
    struct ethhdr *eth = data;
    struct iphdr *ip = data + ETHER_HDR_LEN;
    struct tcphdr *tcp = data + ETHER_HDR_LEN + IP_HDR_LEN;

    // Check if packet is TCP
    if (eth->h_proto != htons(ETH_P_IP) || ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    // Calculate offset to TCP data
    int data_offset = ETHER_HDR_LEN + IP_HDR_LEN + tcp->doff * 4;

    // Bounds check for TLS record type
    if (data + data_offset + 1 > data_end)
        return XDP_PASS;

    // Check if it's a TLS packet
    if (*(uint8_t *)(data + data_offset) != TLS_HANDSHAKE)
        return XDP_PASS;

    // Calculate TLS handshake header length offset
    int tls_handshake_type_offset = data_offset + 5;

    // Bounds check for TLS handshake type
    if (data + tls_handshake_type_offset + 1 > data_end)
        return XDP_PASS;

    // Check if it's a ClientHello message
    if (*(uint8_t *)(data + tls_handshake_type_offset) != TLS_CLIENT_HELLO)
        return XDP_PASS;

    // Calculate TLS handshake length offset
    int tls_handshake_len_offset = tls_handshake_type_offset + 1;

    // Bounds check for TLS handshake length
    if (data + tls_handshake_len_offset + 4 > data_end)
        return XDP_PASS;

    // Calculate the length of the ClientHello message. The length is a 3-byte field.
    int tls_handshake_len = (*(uint8_t *)(data + tls_handshake_len_offset + 2)) +
            ((*(uint8_t *)(data + tls_handshake_len_offset + 1)) << 8) +
            ((*(uint8_t *)(data + tls_handshake_len_offset)) << 16);

    bpf_printk("tls_handshake_len: %d\n", tls_handshake_len);

    if (tls_handshake_len < 0 || tls_handshake_len > 65535)
        return XDP_PASS;

    // Calculate TLS session id length offset, skip the random field
    int tls_session_len_offset = tls_handshake_len_offset + 37;

    // Bounds check for TLS session length
    if (data + tls_session_len_offset + 1 > data_end)
        return XDP_PASS;

    // Calculate the length of the session id. The length is a 1-byte field.
    int tls_session_len = *(uint8_t *)(data + tls_session_len_offset);

    if (tls_session_len < 0 || tls_session_len > 255)
        return XDP_PASS;

    bpf_printk("tls_session_len: %d\n", tls_session_len);

    // Calculate the offset to the TLS chipper suites length
    int tls_cipher_suites_len_offset = tls_session_len_offset + tls_session_len + 1;

    // Bounds check for TLS chipper suites length
    if (data + tls_cipher_suites_len_offset + 2 > data_end)
        return XDP_PASS;

    // Calculate the length of the cipher suites. The length is a 2-byte field.
    int tls_cipher_suites_len = (*(uint8_t *)(data + tls_cipher_suites_len_offset + 1)) +
            ((*(uint8_t *)(data + tls_cipher_suites_len_offset)) << 8);

    bpf_printk("tls_cipher_suites_len: %d\n", tls_cipher_suites_len);

    if (tls_cipher_suites_len < 0 || tls_cipher_suites_len > 65535/2)
        return XDP_PASS;

    int tls_compress_methods_len_offset = tls_cipher_suites_len_offset + tls_cipher_suites_len + 2;

    // Bounds check for TLS compression methods length
    if (data + tls_compress_methods_len_offset + 1 > data_end)
        return XDP_PASS;

    // Calculate the length of the compression methods. The length is a 1-byte field.
    int tls_compress_methods_len = *(uint8_t *)(data + tls_compress_methods_len_offset);

    if (tls_compress_methods_len < 0 || tls_compress_methods_len > 255)
        return XDP_PASS;

    bpf_printk("tls_compress_methods_len: %d\n", tls_compress_methods_len);

    int tls_extensions_len_offset = tls_compress_methods_len_offset + tls_compress_methods_len + 1;

    // Bounds check for TLS extensions length
    if (data + tls_extensions_len_offset + 2 > data_end)
        return XDP_PASS;

    int tls_extensions_len = (*(uint8_t *)(data + tls_extensions_len_offset + 1)) +
            ((*(uint8_t *)(data + tls_extensions_len_offset)) << 8);

    if (tls_extensions_len < 0 || tls_extensions_len > 65535)
        return XDP_PASS;

    bpf_printk("tls_extensions_len: %d\n", tls_extensions_len);

    int offset = tls_extensions_len_offset + 2;

    bpf_printk("offset: %d\n", offset);
    bpf_printk("limit: %d\n", tls_extensions_len_offset + tls_extensions_len + 2);

    for (int i = 0; i < 16; i++) {
        struct extension *ext;

        if (offset > tls_extensions_len_offset + tls_extensions_len + 2)
            return XDP_PASS;

        if (data + offset + sizeof(struct extension) > data_end)
            return XDP_PASS;

        ext = (struct extension *)(data + offset);
        offset += sizeof(struct extension);
        int extension_len = ntohs(ext->len);

        bpf_printk("extension_type: %d\n", ntohs(ext->type));
        bpf_printk("extension_len: %d\n", extension_len);

        if (ntohs(ext->type) == SNI_EXTENSION) {
            if (data + offset + sizeof(struct sni_extension) > data_end)
                return XDP_PASS;

            struct sni_extension *sni_ext = (struct sni_extension *)(data + offset);

            offset += sizeof(struct sni_extension);

            int server_name_len = ntohs(sni_ext->len);
            bpf_printk("server_name_len: %d\n", server_name_len);

            __u32 key    = 0;
            __u64 *count = bpf_map_lookup_elem(&pkt_count, &key);
            if (count) {
                __sync_fetch_and_add(count, 1);
            }

            struct server_name sn;
            for (int i = 0; i < server_name_len; i++) {
                if (data + offset + 1 > data_end) {
                    return XDP_PASS;
                }
                if (i > sizeof(sn.server_name) - 1) {
                    return XDP_PASS;
                }
                sn.server_name[i] = (*(char *)(data + offset));
                offset += 1;
            }
            sn.server_name[server_name_len] = 0;
            //struct server_name sn = {"a"};
            //bpf_xdp_load_bytes(data, offset, &sn.server_name, server_name_len);
            bpf_printk("server_name: %s\n", ((char *)(data + offset)));
            //char domain[] = "alerts.ynet.co.il";
//            if (server_name_len == sizeof(domain) && bpf_strcmp(sni, domain, sni_len) == 0) {
//                return XDP_DROP;
//            }

            return XDP_PASS;
        }

        if (extension_len > 2048)
            return XDP_PASS;

        if (data + offset + extension_len > data_end)
            return XDP_PASS;

        offset += extension_len;
    }

    return XDP_PASS;
}

char __license[] SEC("license") = "Dual MIT/GPL";
