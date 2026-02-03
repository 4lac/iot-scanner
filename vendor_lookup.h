#ifndef VENDOR_LOOKUP_H
#define VENDOR_LOOKUP_H

#include <stdint.h>

void load_oui_database(const char *filename);
const char *lookup_vendor_by_mac(const uint8_t mac[6]);

#endif
