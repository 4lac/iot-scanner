#ifndef SCANN_H
#define SCANN_H

void start_scan(const char *subnet);
void print_devices();
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

#endif
