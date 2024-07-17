#include <arpa/inet.h>
#include <time.h>
#include <linux/wireless.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <linux/if_link.h>
#include <errno.h>
#include <unistd.h> 
#define SNAP_LEN 1518  // Max bytes per packet
#define SIZE_ETHERNET 14
#define WLAN_RADIO_HDR_LEN 8
#define MAX_CHANNELS 11
#define CHANNEL_HOP_INTERVAL 2
//#define CHANNEL_HOP_INTERVAL 10 
#define INTERFACE "wlp0s20f3"
#define PACKET_COUNT_PER_CHANNEL 200
extern void initPacketQueue();

extern int isQueueEmpty();
extern int isQueueFull();

extern void enqueuePacket(const struct pcap_pkthdr *header, const u_char *packet);

extern struct PacketNode dequeuePacket();
