#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <pthread.h> 
#include <signal.h>

#define WLAN_FC_TYPE_MGMT 0x00
#define WLAN_FC_TYPE_CTRL 0x01
#define WLAN_FC_TYPE_DATA 0x02

/*
* Bits in the frame control field.
*/
#define	FC_VERSION(fc)		((fc) & 0x3)
#define	FC_TYPE(fc)		(((fc) >> 2) & 0x3)
#define	FC_SUBTYPE(fc)		(((fc) >> 4) & 0xF)
#define	FC_TO_DS(fc)		((fc) & 0x0100)
#define	FC_FROM_DS(fc)		((fc) & 0x0200)
#define	FC_MORE_FLAG(fc)	((fc) & 0x0400)
#define	FC_RETRY(fc)		((fc) & 0x0800)
#define	FC_POWER_MGMT(fc)	((fc) & 0x1000)
#define	FC_MORE_DATA(fc)	((fc) & 0x2000)
#define	FC_PROTECTED(fc)	((fc) & 0x4000)
#define	FC_ORDER(fc)		((fc) & 0x8000)

#define MAX_QUEUE_SIZE 1000



struct radiotap_header {
    uint8_t it_version;
    uint8_t it_pad;
    uint16_t it_len;
    uint32_t it_present;
};

struct ieee80211_header {
    uint8_t frame_control[2];
    uint8_t duration[2];
    uint8_t receiver_address[ETHER_ADDR_LEN];
    uint8_t transmitter_address[ETHER_ADDR_LEN];
    uint8_t bssid[ETHER_ADDR_LEN];
    uint8_t sequence_control[2];
};

struct ip_header {
    uint8_t  ip_vhl;                 // version and header length
    uint8_t  ip_tos;                 // type of service
    uint16_t ip_len;                 // total length
    uint16_t ip_id;                  // identification
    uint16_t ip_off;                 // fragment offset field
    uint8_t  ip_ttl;                 // time to live
    uint8_t  ip_p;                   // protocol
    uint16_t ip_sum;                 // checksum
    uint32_t ip_src;                 // source address
    uint32_t ip_dst;                 // destination address
};

struct tcp_header {
    uint16_t source_port;
    uint16_t dest_port;
    uint32_t sequence;
    uint32_t acknowledgement;
    uint8_t  data_offset;
    uint8_t  reserved;
    uint8_t  flags;
    uint16_t window;
    uint16_t checksum;
    uint32_t urgent_pointer;
	uint16_t len;  // Added length field
};

struct udp_header {
    uint16_t source_port;
    uint16_t dest_port;
    uint16_t len;
    uint16_t checksum;
	
};

// Define the IEEE 802.11 beacon frame structure (simplified)
struct beacon_frame {
    uint8_t type_subtype;
    uint8_t flags;
    uint16_t duration;
    uint8_t receiver_address[6];
    uint8_t destination_address[6];
    uint8_t transmitter_address[6];
    uint8_t source_address[6];
    uint8_t fragment_number:4;
    uint8_t sequence_number:8;
    // Followed by fixed parameters and tagged parameters...
};


struct PacketNode {
	struct pcap_pkthdr header;
	unsigned char packet[2048]; // Adjust the size as needed
};

struct PacketQueue {
	struct PacketNode queue[MAX_QUEUE_SIZE];
	int front;
	int rear;
	int count;
};


struct fptr{
void (*bfill_fptr)(void *);
void (*bparse_fptr)(void *);
}gfptr;

extern pthread_mutex_t mutex;
extern pthread_cond_t cond;
