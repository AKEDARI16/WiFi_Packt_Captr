#include <stdio.h>
#include <pcap.h>
#include <netinet/if_ether.h> // for Ethernet header definition
#include <inttypes.h> // for PRIu64
#include <netinet/ip.h>       // for IP header definition
#include <netinet/tcp.h>      // for TCP header definition
#include <arpa/inet.h>        // for inet_ntoa function
#include <stdlib.h>
#include <pthread.h>

#define MAX_HANDSHAKE_COUNT 4
typedef struct {
    uint8_t ether_daddr[ETHER_ADDR_LEN]; // Destination MAC address
    uint8_t ether_saddr[ETHER_ADDR_LEN]; // Source MAC address
    uint16_t ether_type; // Ethernet type
} EthernetHeader;
// Structure to represent an EAPOL frame

typedef struct {
    
    uint8_t version;            // EAPOL version
    uint8_t type;               // EAPOL type
    uint16_t length;            // Length of EAPOL frame
    uint8_t descriptor_type;    // Type of Key Descriptor
    uint16_t key_info;          // Key Information field
    uint16_t key_length;        // Length of Key field
    uint64_t replay_counter;    // Replay Counter
    uint8_t key_nonce[32];      // Key Nonce
    uint64_t key_iv;            // Key IV
    uint64_t key_rsc;           // Key RSC
    uint64_t key_id;            // Key ID
    uint8_t key_mic[16];        // Key MIC
    uint16_t key_data_length;   // Length of Key Data field
    uint8_t key_data[0];        // Key Data
    //struct ether_header eth_header;
} EapolFrame;

