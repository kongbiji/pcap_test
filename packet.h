#pragma once
#include <stdint.h>
#include <stdio.h>

#pragma pack(push,1)
typedef struct {
    uint8_t dst_MAC[6];
    uint8_t src_MAC[6];
    uint16_t ether_type;
}Ether;
typedef struct {
    uint8_t v_l;
    uint8_t tos;
    uint16_t total_len;
    uint16_t id;
    uint16_t flag;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dst_ip;
}IP;
typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint8_t offset_reserved;
    uint8_t flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_ptr;
}TCP;
typedef struct {
    Ether eth;
    IP ip;
    TCP tcp;
}Packet;
#pragma pack(pop)

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

void print_MAC(uint8_t *addr){
    printf(" >> %02X:%02X:%02X:%02X:%02X:%02X\n",
           addr[0],addr[1],addr[2],addr[3],
            addr[4],addr[5]);
}
void print_IP(uint32_t ip){
    printf(" >> %d.%d.%d.%d\n", ip&0xFF, (ip>>8)&0xFF, (ip>>16)&0xFF, (ip>>24)&0xFF);
}
