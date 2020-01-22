#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
#include "packet.h"

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }
  printf("success to open pcap handle\n");

  unsigned char * real_data;

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* data;
    
    int res = pcap_next_ex(handle, &header, &data);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;

    Packet * packet = (Packet *)data;

    if(ntohs(packet->eth.ether_type) != 2048){ // If not IPv4
        continue;
    }

    uint8_t ip_header_len = (packet->ip.v_l & 0xF) * 4;
    uint8_t tcp_header_len = (packet->tcp.offset_reserved >> 4) * 4;

    uint16_t ip_len = ntohs(packet->ip.total_len);

    if(packet->ip.protocol != 6){ //if not TCP
        continue;  
    }

    printf("\nIP packet length: %d\n", ip_len);
    printf("IP header len: %d\n",ip_header_len);
    printf("TCP len: %d\n",tcp_header_len);
    printf("----------------------------\n");

    //Ehter Header
    printf("Dst MAC");
    print_MAC(packet->eth.dst_MAC);
    printf("Src MAC");
    print_MAC(packet->eth.src_MAC);
    printf("Ehter type >> %04X\n", ntohs(packet->eth.ether_type));
    printf("----------------------------\n");

    //IP header
    printf("Dst IP");
    print_IP(packet->ip.dst_ip);
    printf("Src IP");
    print_IP(packet->ip.src_ip);
    printf("protocol >> %04X\n",packet->ip.protocol);
    printf("----------------------------\n");

    //TCP header
    printf("Dst port >> %d\n", ntohs(packet->tcp.dst_port));
    printf("Src port >> %d\n", ntohs(packet->tcp.src_port));

    //data
    if(ip_len-ip_header_len-tcp_header_len > 0){
        real_data = (unsigned char *)(packet + sizeof(Ether) + ip_header_len + tcp_header_len);
        printf("data >> \n");
        for(int i = 0; i < ip_len-ip_header_len-tcp_header_len; i++){
            printf("%02X ", real_data[i]);
            if(i % 16 == 0){
                printf("\n");
            }
        }printf("\n");
    }
    printf("============================\n");
  }

  pcap_close(handle);
  return 0;
}
