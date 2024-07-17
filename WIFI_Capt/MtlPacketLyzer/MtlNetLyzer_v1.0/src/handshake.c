#include "handshake.h"
#include "MtlPktLyzer.h"

/*
extern void *(*bfill_fptr)(void *);
extern void *(*bparse_fptr)(void *);
extern pthread_mutex_t mutex;
extern pthread_cond_t cond;

extern void initPacketQueue();

extern int isQueueEmpty();
extern int isQueueFull();

extern void enqueuePacket(const struct pcap_pkthdr *header, const u_char *packet);

extern struct PacketNode dequeuePacket();

void handshake_packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
	pthread_mutex_lock(&mutex);
	while (isQueueFull()) {
		pthread_cond_wait(&cond, &mutex);
	}
	enqueuePacket(pkthdr, packet);
	pthread_cond_signal(&cond);
	pthread_mutex_unlock(&mutex);
}

// Callback function to process captured packets
void processHandshakePacket(struct PacketNode packet) {
    static int handshake_count = 0;
    struct ether_header *eth_header = (struct ether_header *)packet.packet;

    if (ntohs(eth_header->ether_type) != 0x888e) {
        // Not an EAPOL packet, ignore
        return;
    }

    EapolFrame* eapol = (EapolFrame*)(packet.packet + sizeof(struct ether_header));

    u_char *source_mac = eth_header->ether_shost;
    printf(" authenticate with %02x:%02x:%02x:%02x:%02x:%02x\n",
           source_mac[0], source_mac[1], source_mac[2], source_mac[3], source_mac[4], source_mac[5]);

    // Print additional messages
    printf(" send auth to %f ", (double)packet.header.ts.tv_sec + (double)packet.header.ts.tv_usec / 1000000);
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n", source_mac[0], source_mac[1], source_mac[2], source_mac[3], source_mac[4], source_mac[5]);
    printf(" authenticated %f\n", (double)packet.header.ts.tv_sec + (double)packet.header.ts.tv_usec / 1000000);
    printf(" associate with %f ", (double)packet.header.ts.tv_sec + (double)packet.header.ts.tv_usec / 1000000);
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n", source_mac[0], source_mac[1], source_mac[2], source_mac[3], source_mac[4], source_mac[5]);
    printf(" RX AssocResp from %f ", (double)packet.header.ts.tv_sec + (double)packet.header.ts.tv_usec / 1000000);
    printf("%02x:%02x:%02x:%02x:%02x:%02x \n", source_mac[0], source_mac[1], source_mac[2], source_mac[3], source_mac[4], source_mac[5]);

    printf("EAPOL Version: %d\n", ntohs(eapol->version));
    printf("EAPOL Type: %d\n", ntohs(eapol->type));
    printf("EAPOL Length: %d\n", ntohs(eapol->length));
    printf("Descriptor Type: %d\n", eapol->descriptor_type);
    printf("Key Info: 0x%x\n", ntohs(eapol->key_info));
    printf("Key Length: %d\n", ntohs(eapol->key_length));
    printf("Replay Counter: %" PRIu64 "\n", eapol->replay_counter);

    printf("Key Nonce: ");
    for (uint8_t i = 0; i < sizeof(eapol->key_nonce); ++i) {
        printf("%02x ", eapol->key_nonce[i]);
    }
    printf("\n");
    printf("Key IV: %" PRIu64 "\n", eapol->key_iv);
    printf("Key RSC: %" PRIu64 "\n", eapol->key_rsc);
    printf("Key ID: %" PRIu64 "\n", eapol->key_id);

    printf("Key MIC: ");
    for (uint8_t i = 0; i < sizeof(eapol->key_mic); ++i) {
        printf("%02x ", eapol->key_mic[i]);
    }
    printf("\n");

    printf("Key Data Length: %d\n", ntohs(eapol->key_data_length));

    printf("\n\n");

    if (++handshake_count == MAX_HANDSHAKE_COUNT) {
        printf("4-way handshake captured!\n");
        // You can add code here to handle the captured handshake
        exit(0); // Exit the program after capturing the handshake
    }
}

void *handshake_parse_thread() {
    while (1) {
        pthread_mutex_lock(&mutex);
        while (isQueueEmpty()) {
            pthread_cond_wait(&cond, &mutex);
        }
        struct PacketNode packet = dequeuePacket();
        pthread_cond_signal(&cond);
        pthread_mutex_unlock(&mutex);

        processHandshakePacket(packet);
    }
    pthread_exit(NULL);
}

void *handshake_capture_thread(void *arg) {
	printf("in handshake_capture_thread");
	pcap_t *handle = (pcap_t *)arg;
	pcap_loop(handle, -1, handshake_packet_handler, NULL);
	pthread_exit(NULL);
}

void *handshake_thread_implement(char *filter, char *interface, pcap_t *handle) {
    struct bpf_program fp;

    // Further processing based on options
    initPacketQueue();
	
    printf("Interface: %s, Filter: %s\n", interface, filter);
    printf("Capturing from Interface: %s\n", interface);
    
    pthread_t capture_thread, parse_thread;
    if (pthread_create(&capture_thread, NULL, bfill_fptr, (void *)handle) != 0 ||
        pthread_create(&parse_thread, NULL, bparse_fptr, (void *)handle) != 0) {
        fprintf(stderr, "Error creating packet capture or parse thread\n");
        pcap_freecode(&fp); // Free the compiled filter
        pcap_close(handle); // Close pcap handle
        pthread_mutex_destroy(&mutex);
        pthread_cond_destroy(&cond);
        return NULL;
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
}*/

void handshake_packetHandler(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
static int handshake_count = 0;
// Assuming the packet starts with Ethernet header
struct ether_header* eth_header = (struct ether_header*)packet;
    if (ntohs(eth_header->ether_type) != 0x888e) {
        // Not an EAPOL packet, ignore
        return;
    }
   EapolFrame* eapol = (EapolFrame*)(packet + sizeof(struct ether_header));
 
    // Extract the MAC address of the AP from the packet
 u_char* source_mac = eth_header->ether_shost;
    printf(" authenticate with %02x:%02x:%02x:%02x:%02x:%02x\n",
           source_mac[0], source_mac[1], source_mac[2], source_mac[3], source_mac[4], source_mac[5]);

    // Print additional messages
    printf(" send auth to %02f ",(double)pkthdr->ts.tv_sec + (double)pkthdr->ts.tv_usec / 1000000);
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n", source_mac[0], source_mac[1], source_mac[2], source_mac[3], source_mac[4], source_mac[5]);
    printf(" authenticated %02f\n", (double)pkthdr->ts.tv_sec + (double)pkthdr->ts.tv_usec / 1000000);
    printf(" associate with %2f ",(double)pkthdr->ts.tv_sec + (double)pkthdr->ts.tv_usec / 1000000);
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n",source_mac[0], source_mac[1], source_mac[2], source_mac[3], source_mac[4], source_mac[5]);
    printf(" RX AssocResp from %02f ",(double)pkthdr->ts.tv_sec + (double)pkthdr->ts.tv_usec / 1000000);
    printf("%02x:%02x:%02x:%02x:%02x:%02x \n", source_mac[0], source_mac[1], source_mac[2], source_mac[3], source_mac[4], source_mac[5]);
    // Assuming the EAPOL frame starts right after the Ethernet header
    //EapolFrame* eapol = (EapolFrame*)(packet + sizeof(struct ether_header));

    // Print information about the EAPOL frame
    printf("EAPOL Version: %d\n", eapol->version);
    printf("EAPOL Type: %d\n", eapol->type);
    printf("EAPOL Length: %d\n", ntohs(eapol->length));
    printf("Descriptor Type: %d\n", eapol->descriptor_type);
    printf("Key Info: 0x%x\n", ntohs(eapol->key_info));
    printf("Key Length: %d\n", ntohs(eapol->key_length));
    printf("Replay Counter: %" PRIu64 "\n", eapol->replay_counter);

    // Print Key Nonce
    printf("Key Nonce: ");
    for (int i = 0; i < sizeof(eapol->key_nonce); ++i) {
        printf("%02x ", eapol->key_nonce[i]);
    }
    printf("\n");
    printf("Key IV: %" PRIu64 "\n", eapol->key_iv);
    printf("Key RSC: %" PRIu64 "\n", eapol->key_rsc);
    printf("Key ID: %" PRIu64 "\n", eapol->key_id);

    // Print Key MIC
    printf("Key MIC: ");
    for (int i = 0; i < sizeof(eapol->key_mic); ++i) {
        printf("%02x ", eapol->key_mic[i]);
    }
    printf("\n");

    printf("Key Data Length: %d\n", ntohs(eapol->key_data_length));

   // Print Key Data
 
    printf("\n\n");
    if (++handshake_count == MAX_HANDSHAKE_COUNT) {
            printf("4-way handshake captured!\n");
            // You can add code here to handle the captured handshake
            exit(0); // Exit the program after capturing the handshake
        }
}

void *handshake_implement(char *filter, char *interface, pcap_t *handle) {
	
	// Start capturing packets and call packetHandler for each captured packet
    pcap_loop(handle, -1, handshake_packetHandler, NULL);

    // Close the capture handle when done
    pcap_close(handle);
}
