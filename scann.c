
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/select.h>
#include <netdb.h>
#include <errno.h>
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <stdbool.h>

#include "vendor_lookup.h"
#include "scann.h"

#define MAX_DEVICES 256
#define SCAN_DURATION 10
#define SNMP_COMMUNITY "public"

typedef struct {
    uint8_t mac[6];
    uint8_t ip[4];
    char vendor[64];
    char snmp_info[128];
    int is_iot;
    char device_type[64];
} Device;

Device devices[MAX_DEVICES];
int device_count = 0;

bool is_duplicate(const Device *d) {
    for (int i = 0; i < device_count; i++) {
        if (memcmp(devices[i].mac, d->mac, 6) == 0) {
            return true;
        }
    }
    return false;
}

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ether_header *eth = (struct ether_header *)packet;
    if (ntohs(eth->ether_type) != ETHERTYPE_ARP) return;

    struct ether_arp *arp = (struct ether_arp *)(packet + sizeof(struct ether_header));
    Device d;
    memcpy(d.mac, arp->arp_sha, 6);
    memcpy(d.ip, arp->arp_spa, 4);

    const char *vendor = lookup_vendor_by_mac(d.mac);
    strncpy(d.vendor, vendor, sizeof(d.vendor));

  d.is_iot = (strstr(d.vendor, "Espressif") != NULL ||
            strstr(d.vendor, "Amazon")    != NULL ||
            strstr(d.vendor, "TP-Link")   != NULL ||
            strstr(d.vendor, "Xiaomi")    != NULL ||
            strstr(d.vendor, "Tuya")      != NULL ||
            strstr(d.vendor, "Unknown IoT Device") != NULL);

    d.snmp_info[0] = '\0';

    if (!is_duplicate(&d) && device_count < MAX_DEVICES) {
        devices[device_count++] = d;
    }
}

unsigned short checksum(unsigned short *buf, int len) {
    unsigned long sum = 0;
    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }
    if (len) sum += *(unsigned char *)buf;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

void send_icmp_ping(const char *ip_str) {
    struct sockaddr_in addr;
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock < 0) return;

    addr.sin_family = AF_INET;
    inet_pton(AF_INET, ip_str, &(addr.sin_addr));

    struct icmp icmp_pkt;
    memset(&icmp_pkt, 0, sizeof(icmp_pkt));
    icmp_pkt.icmp_type = ICMP_ECHO;
    icmp_pkt.icmp_code = 0;
    icmp_pkt.icmp_id = getpid() & 0xFFFF;
    icmp_pkt.icmp_seq = 1;
    icmp_pkt.icmp_cksum = checksum((unsigned short *)&icmp_pkt, sizeof(icmp_pkt));

    sendto(sock, &icmp_pkt, sizeof(icmp_pkt), 0, (struct sockaddr *)&addr, sizeof(addr));
    close(sock);
}

void try_snmp(Device *d) {
    struct snmp_session session, *ss;
    snmp_sess_init(&session);
    session.version = SNMP_VERSION_1;

    char ip_str[INET_ADDRSTRLEN];
    snprintf(ip_str, sizeof(ip_str), "%d.%d.%d.%d", d->ip[0], d->ip[1], d->ip[2], d->ip[3]);
    session.peername = ip_str;

    session.community = (u_char *)SNMP_COMMUNITY;
    session.community_len = strlen(SNMP_COMMUNITY);

    SOCK_STARTUP;
    ss = snmp_open(&session);
    if (!ss) {
        SOCK_CLEANUP;
        return;
    }

    netsnmp_pdu *pdu = snmp_pdu_create(SNMP_MSG_GET);
    netsnmp_pdu *response;
    oid anOID[MAX_OID_LEN];
    size_t anOID_len = MAX_OID_LEN;

    read_objid(".1.3.6.1.2.1.1.1.0", anOID, &anOID_len);
    snmp_add_null_var(pdu, anOID, anOID_len);

    int status = snmp_synch_response(ss, pdu, &response);

    if (status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR) {
        netsnmp_variable_list *vars = response->variables;
        if (vars->type == ASN_OCTET_STR) {
            snprintf(d->snmp_info, sizeof(d->snmp_info), "%.*s", (int)vars->val_len, (char *)vars->val.string);
            d->is_iot = 1;
        }
    }

    if (response)
        snmp_free_pdu(response);
    snmp_close(ss);
    SOCK_CLEANUP;
}

void scan_icmp_range(const char *base_ip) {
    for (int i = 1; i <= 254; i++) {
        char ip[32];
        snprintf(ip, sizeof(ip), "%s.%d", base_ip, i);
        send_icmp_ping(ip);
        usleep(10000);
    }
}

void start_scan(const char *subnet) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "pcap_findalldevs error: %s\n", errbuf);
        return;
    }

    pcap_if_t *dev = alldevs;
    while (dev && (dev->flags & PCAP_IF_LOOPBACK)) {
        dev = dev->next;
    }

    if (!dev) {
        fprintf(stderr, "No suitable interface found.\n");
        return;
    }

    printf("Using interface: %s\n", dev->name);
    pcap_t *handle = pcap_open_live(dev->name, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "pcap_open_live failed: %s\n", errbuf);
        return;
    }

    struct bpf_program fp;
    if (pcap_compile(handle, &fp, "arp", 0, PCAP_NETMASK_UNKNOWN) == -1 ||
        pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Failed to set ARP filter\n");
        return;
    }

    printf("Scanning ARP packets for %d seconds...\n", SCAN_DURATION);
    time_t start = time(NULL);
    while ((time(NULL) - start) < SCAN_DURATION) {
        struct pcap_pkthdr *header;
        const u_char *packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 1) {
            packet_handler(NULL, header, packet);
        }
    }

    pcap_close(handle);
    pcap_freealldevs(alldevs);

    printf("ARP scan done. Sending ICMP pings to complete discovery...\n");
    scan_icmp_range(subnet);

    for (int i = 0; i < device_count; i++) {
        try_snmp(&devices[i]);
    }
}

void print_devices() {
    printf("\nDiscovered Devices:\n");
    for (int i = 0; i < device_count; i++) {
        Device *d = &devices[i];
        printf("Device %d:\n", i + 1);
        printf("  IP     : %d.%d.%d.%d\n", d->ip[0], d->ip[1], d->ip[2], d->ip[3]);
        printf("  MAC    : %02x:%02x:%02x:%02x:%02x:%02x\n",
               d->mac[0], d->mac[1], d->mac[2], d->mac[3], d->mac[4], d->mac[5]);
        printf("  Vendor : %s\n", d->vendor);
        if (strlen(d->snmp_info)) {
            printf("  SNMP Info: %s\n", d->snmp_info);
        }
        printf("  Type   : %s\n", d->is_iot ? "IoT Device" : "General Device");
        printf("____________________________\n");
    }
}

