
#include <netinet/in.h> // for inet_ntoa
#include <time.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include "MtlPktLyzer.h"
#include "func_dec.h"
#include "dbgprint.h" 
// Add a macro to define the maximum line size for timestamp and packet details
#define MAX_LINE_SIZE 2048



struct PacketQueue packetQueue;

void initPacketQueue() {
	packetQueue.front = 0;
	packetQueue.rear = -1;
	packetQueue.count = 0;
}

int isQueueEmpty() {
	return (packetQueue.count == 0);
}

int isQueueFull() {
	return (packetQueue.count == MAX_QUEUE_SIZE);
}

void enqueuePacket(const struct pcap_pkthdr *header, const u_char *packet) {
	if (!isQueueFull()) {
		packetQueue.rear = (packetQueue.rear + 1) % MAX_QUEUE_SIZE;
		memcpy(&packetQueue.queue[packetQueue.rear].header, header, sizeof(struct pcap_pkthdr));
		memcpy(packetQueue.queue[packetQueue.rear].packet, packet, header->caplen);
		packetQueue.count++;
	}
}

struct PacketNode dequeuePacket() {
	struct PacketNode packet;
	if (!isQueueEmpty()) {
		memcpy(&packet, &packetQueue.queue[packetQueue.front], sizeof(struct PacketNode));
		packetQueue.front = (packetQueue.front + 1) % MAX_QUEUE_SIZE;
		packetQueue.count--;
	}
	return packet;
}

void print_mac(const u_char *mac_addr) {
	printf("%02x:%02x:%02x:%02x:%02x:%02x ", mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5]);
}

void print_ip(uint32_t ip_addr) {
	struct in_addr in;
	in.s_addr = ip_addr;
	printf("%s ", inet_ntoa(in));
}

void print_tcp_header(const struct tcp_header *tcp_hdr) {
	printf("TCP: Source Port: %u, Dest Port: %u\n", ntohs(tcp_hdr->source_port), ntohs(tcp_hdr->dest_port));
    dbg_log(MSG_DEBUG,"TCP: Source Port: %u, Dest Port: %u\n", ntohs(tcp_hdr->source_port), ntohs(tcp_hdr->dest_port));
}

void print_udp_header(const struct udp_header *udp_hdr) {
	printf("UDP: Source Port: %u, Dest Port: %u, Length: %u\n", ntohs(udp_hdr->source_port), ntohs(udp_hdr->dest_port), ntohs(udp_hdr->len));
    dbg_log(MSG_DEBUG,"UDP: Source Port: %u, Dest Port: %u, Length: %u\n", ntohs(udp_hdr->source_port), ntohs(udp_hdr->dest_port), ntohs(udp_hdr->len));
}

// Array of frame type names
const char *frame_type_names[] = {"Management", "Control", "Data"};

// Arrays of frame subtype names for each frame type
const char *mgmt_frame_subtypes[] = {"Association Request", "Association Response", "Reassociation Request", 
                                     "Reassociation Response", "Probe Request", "Probe Response", "Reserved", 
                                     "Beacon", "ATIM", "Disassociation", "Authentication", "Deauthentication", "Action"};

const char *ctrl_frame_subtypes[] = {"Reserved", "Reserved", "Reserved", "Reserved", "Reserved", "Reserved", "Reserved", 
                                     "Block Ack Request", "Block Ack", "PS-Poll", "RTS", "CTS", "ACK", "CF-End", 
                                     "CF-End + CF-Ack", "Data"};

const char *data_frame_subtypes[] = {"Data", "Data + CF-ACK", "Data + CF-Poll", "Data + CF-ACK + CF-Poll", 
                                     "Null Function (no data)", "CF-ACK (no data)", "CF-Poll (no data)", 
                                     "CF-ACK + CF-Poll (no data)", "QoS Data", "QoS Data + CF-ACK", 
                                     "QoS Data + CF-Poll", "QoS Data + CF-ACK + CF-Poll", "QoS Null", 
                                     "Reserved", "QoS CF-Poll (no data)", "QoS CF-ACK + CF-Poll (no data)"};



void connect_packet_handler(u_char *user,const struct pcap_pkthdr *pkthdr, const u_char *packet) {
	pthread_mutex_lock(&mutex);
	while (isQueueFull()) {
		pthread_cond_wait(&cond, &mutex);
	}
	enqueuePacket(pkthdr, packet);
	pthread_cond_signal(&cond);
	pthread_mutex_unlock(&mutex);
}

void connect_capture_thread(void *arg) {
	pcap_t *handle = (pcap_t *)arg;
  //  printf("enter into cconnect_capture_thread");
	pcap_loop(handle, -1, connect_packet_handler, NULL);
	pthread_exit(NULL);
}


void connect_parse_thread() {
    //pcap_t *handle = (pcap_t *)arg;
    while (1) {
        pthread_mutex_lock(&mutex);
        while (isQueueEmpty()) {
            pthread_cond_wait(&cond, &mutex);
        }
        struct PacketNode packet = dequeuePacket();
        pthread_cond_signal(&cond);
        pthread_mutex_unlock(&mutex);
        
        // Process the packet
        struct radiotap_header *radiotap_hdr = (struct radiotap_header *)packet.packet;
        const u_char *payload = packet.packet + radiotap_hdr->it_len;

        // Check for presence of 802.11 header
        if (packet.header.len < sizeof(struct radiotap_header) + sizeof(struct ieee80211_header)) {
            printf("Packet too short for 802.11 header\n");
			dbg_log(MSG_DEBUG,"Packet too short for 802.11 header");
            continue;
        }

		struct ieee80211_header *wifi_hdr = (struct ieee80211_header *)payload;

			// Extract frame type and subtype
		uint8_t frame_type = (wifi_hdr->frame_control[0] & 0x0C) >> 2;
		uint8_t frame_subtype = wifi_hdr->frame_control[0] & 0xF;

		// Prepare a single line with all details including timestamp, MAC addresses, and frame types
		char line[MAX_LINE_SIZE];
		time_t now = time(NULL);
		struct tm *tm_info = localtime(&now);

		// Check if the MAC address is the Null MAC address "00:00:00:00:00:00"
		if (memcmp(wifi_hdr->transmitter_address, "\x00\x00\x00\x00\x00\x00", 6) == 0 ||
			memcmp(wifi_hdr->receiver_address, "\x00\x00\x00\x00\x00\x00", 6) == 0) {
			// MAC address is Null, print as "Broadcast"
			snprintf(line, sizeof(line), "%04d-%02d-%02d %02d:%02d:%02d Broadcast -> Broadcast Frame Type: %s, Frame Subtype: %s, ",
					 tm_info->tm_year + 1900, tm_info->tm_mon + 1, tm_info->tm_mday,
					 tm_info->tm_hour, tm_info->tm_min, tm_info->tm_sec,
					 frame_type_names[frame_type],
					 frame_type == 0 ? mgmt_frame_subtypes[frame_subtype] :
					 frame_type == 1 ? ctrl_frame_subtypes[frame_subtype] :
					 frame_type == 2 ? data_frame_subtypes[frame_subtype] : "Reserved");
		} else {
			// MAC address is not Null, print the actual MAC addresses
			snprintf(line, sizeof(line), "%04d-%02d-%02d %02d:%02d:%02d %02x:%02x:%02x:%02x:%02x:%02x -> %02x:%02x:%02x:%02x:%02x:%02x Frame Type: %s, Frame Subtype: %s, ",
					 tm_info->tm_year + 1900, tm_info->tm_mon + 1, tm_info->tm_mday,
					 tm_info->tm_hour, tm_info->tm_min, tm_info->tm_sec,
					 wifi_hdr->transmitter_address[0], wifi_hdr->transmitter_address[1],
					 wifi_hdr->transmitter_address[2], wifi_hdr->transmitter_address[3],
					 wifi_hdr->transmitter_address[4], wifi_hdr->transmitter_address[5],
					 wifi_hdr->receiver_address[0], wifi_hdr->receiver_address[1],
					 wifi_hdr->receiver_address[2], wifi_hdr->receiver_address[3],
					 wifi_hdr->receiver_address[4], wifi_hdr->receiver_address[5],
					 frame_type_names[frame_type],
					 frame_type == 0 ? mgmt_frame_subtypes[frame_subtype] :
					 frame_type == 1 ? ctrl_frame_subtypes[frame_subtype] :
					 frame_type == 2 ? data_frame_subtypes[frame_subtype] : "Reserved");
		}

		// Check for IP layer based on frame type
		if (frame_type == 2) {
			// Check for minimum IP header size
			if (packet.header.len < sizeof(struct radiotap_header) + sizeof(struct ieee80211_header) + sizeof(struct ip_header)) {
				printf("Packet too short for IP header\n");
				dbg_log(MSG_DEBUG,"Packet too short for IP header");
				continue;
			}

			payload += sizeof(struct ieee80211_header);  // Skip to IP header

			struct ip_header *ip_hdr = (struct ip_header *)payload;

			// Append IP addresses to the line
			snprintf(line + strlen(line), sizeof(line) - strlen(line), "IP: %s -> %s, ",
					 inet_ntoa(*(struct in_addr *)&ip_hdr->ip_src), inet_ntoa(*(struct in_addr *)&ip_hdr->ip_dst));

			// Extract protocol type
			uint8_t protocol = ip_hdr->ip_p;

			// Check for TCP or UDP based on protocol
			if (protocol == IPPROTO_TCP) {
				// Check for minimum TCP header size
				if (packet.header.len < sizeof(struct radiotap_header) + sizeof(struct ieee80211_header) + sizeof(struct ip_header) + sizeof(struct tcp_header)) {
					printf("Packet too short for TCP header\n");
					dbg_log(MSG_DEBUG,"Packet too short for TCP header");
					continue;
				}

				payload += sizeof(struct ip_header);  // Skip to TCP header

				struct tcp_header *tcp_hdr = (struct tcp_header *)payload;

				// Append TCP header details to the line
				snprintf(line + strlen(line), sizeof(line) - strlen(line), "TCP: Source Port: %u, Dest Port: %u, ",
						 ntohs(tcp_hdr->source_port), ntohs(tcp_hdr->dest_port));
			} else if (protocol == IPPROTO_UDP) {
				// Check for minimum UDP header size
				if (packet.header.len < sizeof(struct radiotap_header) + sizeof(struct ieee80211_header) + sizeof(struct ip_header) + sizeof(struct udp_header)) {
					printf("Packet too short for UDP header\n");
					dbg_log(MSG_DEBUG,"Packet too short for UDP header");
					continue;
				}

				payload += sizeof(struct ip_header);  // Skip to UDP header

				struct udp_header *udp_hdr = (struct udp_header *)payload;

				// Append UDP header details to the line
				snprintf(line + strlen(line), sizeof(line) - strlen(line), "UDP: Source Port: %u, Dest Port: %u, Length: %u, ",
						 ntohs(udp_hdr->source_port), ntohs(udp_hdr->dest_port), ntohs(udp_hdr->len));
			} else {
				// Append unknown protocol to the line
				snprintf(line + strlen(line), sizeof(line) - strlen(line), "Unknown protocol: %u, ", protocol);
			}
		}

		// Print the complete line with all details and timestamp
		printf("%s", line);
		dbg_log(MSG_DEBUG,"%s", line);
		
	}
    pthread_exit(NULL);
}


u_int8_t connect_thread_implement(char *filter, char *interface, pcap_t *handle, struct fptr *gfptr) {
    struct bpf_program fp;

    // Further processing based on options
    initPacketQueue();
	
    printf("Interface: %s, Filter: %s\n", interface, filter);
	dbg_log(MSG_DEBUG,"Interface: %s, Filter: %s", interface, filter);
    printf("Capturing from Interface: %s\n", interface);
    dbg_log(MSG_DEBUG,"Capturing from Interface: %s", interface);

    pthread_t capture_thread, parse_thread;
    printf("thread creation in process");
	dbg_log(MSG_DEBUG,"thread creation in process");

    if (pthread_create(&capture_thread, NULL, (void* (*)(void*))gfptr->bfill_fptr, (void *)handle) != 0 ||
        pthread_create(&parse_thread, NULL, (void* (*)(void*))gfptr->bparse_fptr, (void *)handle) != 0) {
        fprintf(stderr, "Error creating packet capture or parse thread\n");
		dbg_log(MSG_DEBUG,"Error creating packet capture or parse thread\n");
        pcap_freecode(&fp); // Free the compiled filter
        pcap_close(handle); // Close pcap handle
        pthread_mutex_destroy(&mutex);
        pthread_cond_destroy(&cond);
        return EXIT_FAILURE;
    }

    // Wait for the packet capture thread to finish
    pthread_join(capture_thread, NULL);
    pthread_join(parse_thread, NULL);

    // Cleanup
    pcap_freecode(&fp); // Free the compiled filter
    pcap_close(handle); // Close pcap handle
    pthread_mutex_destroy(&mutex);
    pthread_cond_destroy(&cond);
    return EXIT_SUCCESS;
}