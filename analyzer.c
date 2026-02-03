#include <pcap.h>
#include <stdio.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <string.h>

void analyze_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ip *ip_hdr = (struct ip *)(packet + 14); // Skip Ethernet header

    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_hdr->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_hdr->ip_dst), dst_ip, INET_ADDRSTRLEN);

    printf("Protocol: ");
    switch (ip_hdr->ip_p) {
        case IPPROTO_TCP: {
            struct tcphdr *tcp_hdr = (struct tcphdr *)(packet + 14 + (ip_hdr->ip_hl * 4));
            printf("TCP | %s:%d --> %s:%d\n", src_ip, ntohs(tcp_hdr->th_sport), dst_ip, ntohs(tcp_hdr->th_dport));
            break;
        }
        case IPPROTO_UDP: {
            struct udphdr *udp_hdr = (struct udphdr *)(packet + 14 + (ip_hdr->ip_hl * 4));
            printf("UDP | %s:%d --> %s:%d\n", src_ip, ntohs(udp_hdr->uh_sport), dst_ip, ntohs(udp_hdr->uh_dport));
            break;
        }
        case IPPROTO_ICMP:
            printf("ICMP | %s --> %s\n", src_ip, dst_ip);
            break;
        default:
            printf("Other | %s --> %s\n", src_ip, dst_ip);
            break;
    }
}

void start_analysis(const char *interface) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "Couldn't open device %s: %s\n", interface, errbuf);
        return;
    }

    printf("Analyzing packets on interface: %s\n", interface);
    pcap_loop(handle, 0, packet_handler, NULL);

    pcap_close(handle);
}
