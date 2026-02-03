#include <stdio.h>
#include "scann.h"
#include "vendor_lookup.h"

int main() {
   
    load_oui_database("ouis.txt");

    printf("\nStarting ARP/ICMP/SNMP scan on current network...\n\n");

    
    start_scan("192.168.1");

    
    print_devices();

    printf("\nScan complete.\n");
    return 0;
}
