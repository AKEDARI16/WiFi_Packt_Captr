#include "handshake.h"
#include "MtlPktLyzer.h"
#include "func_dec.h"
#include "dbgprint.h" 

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
    dbg_log(MSG_DEBUG," authenticate with %02x:%02x:%02x:%02x:%02x:%02x",
           source_mac[0], source_mac[1], source_mac[2], source_mac[3], source_mac[4], source_mac[5]); 
    // Print additional messages
    printf(" send auth to %02f ",(double)pkthdr->ts.tv_sec + (double)pkthdr->ts.tv_usec / 1000000);
    dbg_log(MSG_DEBUG," send auth to %02f ",(double)pkthdr->ts.tv_sec + (double)pkthdr->ts.tv_usec / 1000000);
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n", source_mac[0], source_mac[1], source_mac[2], source_mac[3], source_mac[4], source_mac[5]);
    dbg_log(MSG_DEBUG,"%02x:%02x:%02x:%02x:%02x:%02x", source_mac[0], source_mac[1], source_mac[2], source_mac[3], source_mac[4], source_mac[5]);
    printf(" authenticated %02f\n", (double)pkthdr->ts.tv_sec + (double)pkthdr->ts.tv_usec / 1000000);
    dbg_log(MSG_DEBUG," authenticated %02f\n", (double)pkthdr->ts.tv_sec + (double)pkthdr->ts.tv_usec / 1000000);
    printf(" associate with %2f ",(double)pkthdr->ts.tv_sec + (double)pkthdr->ts.tv_usec / 1000000);
    dbg_log(MSG_DEBUG," associate with %2f ",(double)pkthdr->ts.tv_sec + (double)pkthdr->ts.tv_usec / 1000000);
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n",source_mac[0], source_mac[1], source_mac[2], source_mac[3], source_mac[4], source_mac[5]);
    dbg_log(MSG_DEBUG,"%02x:%02x:%02x:%02x:%02x:%02x\n",source_mac[0], source_mac[1], source_mac[2], source_mac[3], source_mac[4], source_mac[5]);
    printf(" RX AssocResp from %02f ",(double)pkthdr->ts.tv_sec + (double)pkthdr->ts.tv_usec / 1000000);
    dbg_log(MSG_DEBUG," RX AssocResp from %02f ",(double)pkthdr->ts.tv_sec + (double)pkthdr->ts.tv_usec / 1000000);
    printf("%02x:%02x:%02x:%02x:%02x:%02x \n", source_mac[0], source_mac[1], source_mac[2], source_mac[3], source_mac[4], source_mac[5]);
    
    dbg_log(MSG_DEBUG,"%02x:%02x:%02x:%02x:%02x:%02x", source_mac[0], source_mac[1], source_mac[2], source_mac[3], source_mac[4], source_mac[5]);
    // Assuming the EAPOL frame starts right after the Ethernet header
    //EapolFrame* eapol = (EapolFrame*)(packet + sizeof(struct ether_header));

    // Print information about the EAPOL frame
    printf("EAPOL Version: %d\n", eapol->version);
    dbg_log(MSG_DEBUG,"EAPOL Version: %d\n", eapol->version);
    printf("EAPOL Type: %d\n", eapol->type);
    dbg_log(MSG_DEBUG,"EAPOL Type: %d\n", eapol->type);
    printf("EAPOL Length: %d\n", ntohs(eapol->length));
    dbg_log(MSG_DEBUG,"EAPOL Type: %d\n", eapol->type);
    printf("Descriptor Type: %d\n", eapol->descriptor_type);
    dbg_log(MSG_DEBUG,"Descriptor Type: %d\n", eapol->descriptor_type);
    printf("Key Info: 0x%x\n", ntohs(eapol->key_info));
    dbg_log(MSG_DEBUG,"Key Info: 0x%x\n", ntohs(eapol->key_info));
    printf("Key Length: %d\n", ntohs(eapol->key_length));
    dbg_log(MSG_DEBUG,"Key Length: %d\n", ntohs(eapol->key_length));
    printf("Replay Counter: %" PRIu64 "\n", eapol->replay_counter);
    dbg_log(MSG_DEBUG,"Replay Counter: %" PRIu64 "\n", eapol->replay_counter);
    
    // Print Key Nonce
    printf("Key Nonce: ");
    dbg_log(MSG_DEBUG,"Key Nonce: ");
    for (int i = 0; i < sizeof(eapol->key_nonce); ++i) {
        printf("%02x ", eapol->key_nonce[i]);
        dbg_log(MSG_DEBUG,"%02x ", eapol->key_nonce[i]);
    }
    printf("\n");
    printf("Key IV: %" PRIu64 "\n", eapol->key_iv);
    dbg_log(MSG_DEBUG,"Key IV: %" PRIu64 "\n", eapol->key_iv);
    printf("Key RSC: %" PRIu64 "\n", eapol->key_rsc);
    dbg_log(MSG_DEBUG,"Key RSC: %" PRIu64 "\n", eapol->key_rsc);
    printf("Key ID: %" PRIu64 "\n", eapol->key_id);
    dbg_log(MSG_DEBUG,"Key ID: %" PRIu64 "\n", eapol->key_id);
    // Print Key MIC
    printf("Key MIC: ");
    dbg_log(MSG_DEBUG,"Key MIC: ");
    for (int i = 0; i < sizeof(eapol->key_mic); ++i) {
        printf("%02x ", eapol->key_mic[i]);
        dbg_log(MSG_DEBUG,"%02x ", eapol->key_mic[i]);
    }
    printf("\n");

    printf("Key Data Length: %d\n", ntohs(eapol->key_data_length));
    dbg_log(MSG_DEBUG,"Key Data Length: %d\n", ntohs(eapol->key_data_length));

   // Print Key Data
 
    printf("\n\n");
    if (++handshake_count == MAX_HANDSHAKE_COUNT) {
            printf("4-way handshake captured!\n");
            dbg_log(MSG_DEBUG,"4-way handshake captured!\n");
            // You can add code here to handle the captured handshake
            exit(0); // Exit the program after capturing the handshake
        }
}

void handshake_implement(char *filter, char *interface, pcap_t *handle) {
	
	// Start capturing packets and call packetHandler for each captured packet
    pcap_loop(handle, -1, handshake_packetHandler, NULL);

    // Close the capture handle when done
    pcap_close(handle);
}
