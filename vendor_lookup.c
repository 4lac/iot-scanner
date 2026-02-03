#include "vendor_lookup.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define MAX_OUI 100000

typedef struct {
    char prefix[16];
    char vendor[256];
} OUIEntry;

OUIEntry oui_list[MAX_OUI];
int oui_count = 0;

void normalize_mac_prefix(char *input, char *output) {
    //input: "001A2B" or "00-1A-2B"
    //output: "00:1A:2B"
    if (strlen(input) == 6) {
        snprintf(output, 9, "%c%c:%c%c:%c%c",
                 input[0], input[1], input[2], input[3], input[4], input[5]);
    } else if (strlen(input) == 8 && input[2] == '-' && input[5] == '-') {
        snprintf(output, 9, "%c%c:%c%c:%c%c",
                 input[0], input[1], input[3], input[4], input[6], input[7]);
    } else {
        strncpy(output, input, 9); // fallback
    }
}
//hhere
const char *lookup_vendor_by_mac(const uint8_t mac[6]) {
    static char unknown[] = "Unknown";
    char mac_prefix[9];
    snprintf(mac_prefix, sizeof(mac_prefix), "%02x:%02x:%02x", mac[0], mac[1], mac[2]);

    //printf("[DEBUG] Searching for: %s\n", mac_prefix);

    for (int i = 0; i < oui_count; i++) {
        if (strcasecmp(mac_prefix, oui_list[i].prefix) == 0) {
            printf("[DEBUG] Comparing %s with %s\n", mac_prefix, oui_list[i].prefix);

            printf("[MATCH] Found vendor: %s\n", oui_list[i].vendor);
            return oui_list[i].vendor;
        }
    }

    return unknown;
}
/*const char *lookup_vendor_by_mac(const uint8_t mac[6]) {
    static char unknown[] = "Unknown";
    static char vendor[256];
    char mac_prefix[9];
    snprintf(mac_prefix, sizeof(mac_prefix), "%02X:%02X:%02X", mac[0], mac[1], mac[2]);

    FILE *file = fopen(OUI_FILE, "r");
    if (!file) {
        perror("Failed to open OUI database");
        return unknown;
    }

    char line[512];
    while (fgets(line, sizeof(line), file)) {
        line[strcspn(line, "\n")] = '\0'; // إزالة نهاية السطر
        char *comma = strchr(line, ',');
        if (comma) {
            *comma = '\0'; // فصل البادئة عن اسم الشركة
            if (strcasecmp(mac_prefix, line) == 0) {
                strncpy(vendor, comma + 1, sizeof(vendor));
                fclose(file);
                return vendor;
            }
        }
    }*/
/*for (int i = 0; i < oui_count; i++) {
    -printf("[DEBUG] Comparing '%s' with '%s'\n", mac_prefix, oui_list[i].prefix);
    if (strcasecmp(mac_prefix, oui_list[i].prefix) == 0) {
        -printf("[MATCH] Found vendor: %s\n", oui_list[i].vendor);
        return oui_list[i].vendor;
    }
}
*/

void load_oui_database(const char *filename) {
    FILE *file = fopen(filename, "r");
    -printf("[DEBUG] Loaded OUI: '%s' → '%s'\n", oui_list[oui_count].prefix, oui_list[oui_count].vendor);

    if (!file) {
        perror("Failed to open OUI database");
        return;
    }

    char line[512];
    while (fgets(line, sizeof(line), file) && oui_count < MAX_OUI){
        line[strcspn(line, "\n")] = '\0';
        char *comma = strchr(line, ',');
        if (comma) {
            *comma = '\0';
            strncpy(oui_list[oui_count].prefix, line, sizeof(oui_list[oui_count].prefix));
            strncpy(oui_list[oui_count].vendor, comma + 1, sizeof(oui_list[oui_count].vendor));
            -printf("[DEBUG] Loaded OUI: %s → %s\n", oui_list[oui_count].prefix, oui_list[oui_count].vendor);//hereee
            oui_count++;
        }
    }

    fclose(file);
    -printf("[INFO] Total OUI entries loaded: %d\n", oui_count);

}/*
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define OUI_FILE "oui.txt" 

const char *lookup_vendor_by_mac(const uint8_t mac[6]) {
    static char unknown[] = "Unknown";
    static char vendor[256];
    char mac_prefix[9];
    snprintf(mac_prefix, sizeof(mac_prefix), "%02X:%02X:%02X", mac[0], mac[1], mac[2]);

    FILE *file = fopen(OUI_FILE, "r");
    if (!file) {
        perror("Failed to open OUI database");
        return unknown;
    }

    char line[512];
    while (fgets(line, sizeof(line), file)) {
        line[strcspn(line, "\n")] = '\0'; // إزالة نهاية السطر
        char *comma = strchr(line, ',');
        if (comma) {
            *comma = '\0'; // فصل البادئة عن اسم الشركة
            if (strcasecmp(mac_prefix, line) == 0) {
                strncpy(vendor, comma + 1, sizeof(vendor));
                fclose(file);
                return vendor;
            }
        }
    }

    fclose(file);
    printf("[INFO] Total OUI entries loaded: %d\n", oui_count);
    return unknown;
}*/