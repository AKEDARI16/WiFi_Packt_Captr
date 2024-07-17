#include "MtlPktLyzer.h"
#include "scan.h"
#include "func_dec.h"
#include "dbgprint.h" 


// Define a simple function to print MAC addresses in a readable format
void print_mac_address(uint8_t *addr) {
    for (int i = 0; i < 5; ++i) {
        printf("%02x:", addr[i]);
    }
    printf("%02x ", addr[5]);
}

void print_da_address(const uint8_t *addr) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x ", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
    dbg_log(MSG_DEBUG,"%02x:%02x:%02x:%02x:%02x:%02x ", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
}

void print_sa_address(const uint8_t *addr) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x ", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
    dbg_log(MSG_DEBUG,"%02x:%02x:%02x:%02x:%02x:%02x ", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
}


void extract_ssid(const u_char *tagged_params, size_t length) {
    size_t i = 0;
    while (i < length) {
        uint8_t tag_type = tagged_params[i];
        uint8_t tag_len = tagged_params[i + 1];
        if (tag_type == 0) { // SSID tag type
            printf("Beacon(");
            dbg_log(MSG_DEBUG,"Beacon(");
            for (int j = 0; j < tag_len; ++j) {
                char ssid_char = tagged_params[i + 2 + j];
                printf("%c", ssid_char);
                dbg_log(MSG_DEBUG,"%c",ssid_char );
            }
            break;
        }
        i += 2 + tag_len; // Move to the next tag
    }
    printf(")");
    dbg_log(MSG_DEBUG,")");
}

void print_supported_rates(const uint8_t *rates, int len) {
    printf("[");
    dbg_log(MSG_DEBUG,"[");
    for (int i = 0; i < len; i++) {
        printf("%.1f%s ", (rates[i] & 0x7F) * 0.5, (rates[i] & 0x80) ? "*" : "");
        dbg_log(MSG_DEBUG,"%.1f%s ", (rates[i] & 0x7F) * 0.5, (rates[i] & 0x80) ? "*" : "");
    }
    printf("Mbit] ");
    dbg_log(MSG_DEBUG,"Mbit] ");
}


int determine_offset(const uint8_t *packet) {
    // Check if the packet starts with a radiotap header
    // A radiotap header typically starts with a version byte (0x00) followed by a length field
    // The length field indicates the total length of the radiotap header
    if (packet[0] == 0x00 && packet[1] > 0) {
        // The length of the radiotap header is stored in the second byte
        int radiotap_length = packet[1];

        // The IEEE 802.11 header usually starts after the radiotap header
        // Add the length of the radiotap header to get the offset
        int offset = radiotap_length;

        return offset;
    } else {
        // If there's no radiotap header, assume the IEEE 802.11 header starts at the beginning of the packet
        return 0;
    }
}

void scan_parse_thread(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    printf("enter into the scan_parse_thread\n");
    dbg_log(MSG_DEBUG,"enter into the scan_parse_thread\n");
    while (1) {
        pthread_mutex_lock(&mutex);
        while (isQueueEmpty()) {
            pthread_cond_wait(&cond, &mutex);
        }
        struct PacketNode packet = dequeuePacket();
        pthread_cond_signal(&cond);
        pthread_mutex_unlock(&mutex);

        struct tm *ltime;
        char timestr[16];
        time_t local_tv_sec;

        local_tv_sec = packet.header.ts.tv_sec;
        ltime = localtime(&local_tv_sec);
        strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);

        printf("%s.%06ld ", timestr, packet.header.ts.tv_usec);
        dbg_log(MSG_DEBUG,"%s.%06ld ", timestr, packet.header.ts.tv_usec);

        // Assuming the packet starts with a radiotap header
        struct radiotap_header *rth = (struct radiotap_header *)(packet.packet);

        // Skipping the radiotap header for simplicity; you'd parse specific fields as needed
        int header_len = rth->it_len;

        // Now, get to the beacon frame
        struct beacon_frame *bf = (struct beacon_frame *)(packet.packet + header_len);

        // Extract and print the BSSID (transmitter address for beacon frames)
        printf("BSSID:");
        dbg_log(MSG_DEBUG,"BSSID:");
        print_mac_address(bf->transmitter_address);

        // Pointer to the start of the IEEE 802.11 header, right after the Radiotap header
        const uint8_t *ieee80211_header = packet.packet + header_len;

        // Destination Address is the first address field in the 802.11 header for management frames
        const uint8_t *da = ieee80211_header + 4; // Skipping Frame Control (2 bytes) and Duration (2 bytes)

        // Print the Destination Address
        printf("DA:");
        dbg_log(MSG_DEBUG,"DA:");
        print_da_address(da);

        // Assuming the IEEE 802.11 header directly follows the Radiotap header
        ieee80211_header = packet.packet + header_len;

        // In a typical management frame like a beacon, DA, SA, and BSSID can essentially hold the same value.
        // For educational purposes, we're treating the third MAC address as the Source Address (SA) here.
        const uint8_t *sa = ieee80211_header + 4 + 6; // Skipping Frame Control (2 bytes), Duration (2 bytes), and DA (6 bytes)

        // Print the Source Address
        printf("SA:");
        dbg_log(MSG_DEBUG,"SA:");
        print_sa_address(sa);
        //printf("\n");

        bf = (struct beacon_frame *)(packet.packet + header_len + 24);

        // Tagged parameters start after the fixed parameters of the beacon frame
        // Fixed parameters are 12 bytes, but this could vary, adjust accordingly
        const u_char *tagged_params = packet.packet + header_len + 24 + 12;
        size_t params_length = packet.header.caplen - (header_len + 24 + 12);

        // Extract and print the SSID
        extract_ssid(tagged_params, params_length);

        int ieee80211_header_offset = 0/*determine_offset(packet)*//* offset value here */; // This needs to be determined dynamically or set based on your environment
        const uint8_t *frame_body = packet.packet + ieee80211_header_offset;

        // Assuming we're directly at the frame body of a Beacon frame...
        // Skip fixed parameters of Beacon frame to reach the tagged parameters
        int fixed_parameters_length = 12; // Timestamp (8 bytes) + Beacon Interval (2 bytes) + Capability Info (2 bytes)
        tagged_params = frame_body + fixed_parameters_length;
        int tagged_params_length = packet.header.caplen - ieee80211_header_offset - fixed_parameters_length;

        // Parse tagged parameters for Supported Rates (ID 1), Extended Supported Rates (ID 50), and DS Parameter Set (ID 3)
        int index = 0;
        while (index < tagged_params_length) {
            uint8_t id = tagged_params[index];
            uint8_t len = tagged_params[index + 1];
            const uint8_t *data = &tagged_params[index + 2];

            switch (id) {
                case 1: // Supported Rates
                    printf(" Supported Rates:");
                    dbg_log(MSG_DEBUG," Supported Rates:");
                    print_supported_rates(data, len);
                    break;
                case 3: // DS Parameter Set (Channel)
                    printf(" CH: %d, ", data[0]);
                    dbg_log(MSG_DEBUG," CH: %d, ", data[0]);
                    break;
                case 50: // Extended Supported Rates
                    printf(" Extended Supported Rates:");
                    dbg_log(MSG_DEBUG," Extended Supported Rates:");
                    print_supported_rates(data, len);
                    break;
            }
            index += len + 2; // Move to the next tag
        }

        // Extracting the Capability Info directly for Privacy bit
        const uint16_t *capability_info = (const uint16_t *)(frame_body + 10); // Offset 10 within the beacon frame body
        printf(" PRIVACY: %s\n", (*capability_info & 0x0010) ? "Yes" : "No");
        dbg_log(MSG_DEBUG," PRIVACY: %s\n", (*capability_info & 0x0010) ? "Yes" : "No");

        printf("\n");
    }

    pthread_exit(NULL);
}


int setChannel(const char *interface, int channel) {
    // Calculate the length of the command
    size_t command_length = snprintf(NULL, 0, "sudo iw dev %s set channel %d", interface, channel) + 1;

    // Allocate memory for the command
    char *command = (char *)malloc(command_length * sizeof(char));
    if (command == NULL) {
        perror("Memory allocation failed");
        return -1; // Return error
    }

    // Construct the command
    snprintf(command, command_length, "sudo iw dev %s set channel %d",interface,channel);

    // Execute command
    int ret = system(command);
    printf("%s \n command =====",command);
    if (ret != 0) {
        fprintf(stderr, "Failed to set channel %d: %s\n", channel, strerror(errno));
        dbg_log(MSG_DEBUG,"Failed to set channel %d: %s\n", channel, strerror(errno));

        free(command); // Free dynamically allocated memory
        return -1; // Return error
    }
    // Free dynamically allocated memory
    free(command);

    return 0; // Success
}
void scan_packet_handler(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
	pthread_mutex_lock(&mutex);
	while (isQueueFull()) {
		pthread_cond_wait(&cond, &mutex);
	}
	enqueuePacket(pkthdr, packet);
	pthread_cond_signal(&cond);
	pthread_mutex_unlock(&mutex);
}

/*void scan_capture_thread(void *arg) {
// Start the capture
   // pcap_loop(handle, -1, got_packet, NULL);
   int channel;
  for (channel = 1; channel <= MAX_CHANNELS; channel++) {
        if (setChannel(INTERFACE, channel) != 0) {
            fprintf(stderr, "Failed to set channel %d\n", channel);
            continue;
        }
    printf("Channel %d: Waiting for %d seconds and capturing beacons...\n", channel, CHANNEL_HOP_INTERVAL);


	pcap_t *handle = (pcap_t *)arg;
   // pcap_loop(handle, -1, scan_packet_handler, NULL);
   if (pcap_loop(handle, PACKET_COUNT_PER_CHANNEL, scan_packet_handler, NULL) != 0) {
            fprintf(stderr, "Error capturing packets on channel %d\n", channel);
            break; // Exit the loop if an error occurs
        }
	
    // Wait for a while before hopping to the next channel
   else {
        printf("enter into else state\n");
        sleep(CHANNEL_HOP_INTERVAL);
        goto loop;
         continue;   
    }
    sleep(CHANNEL_HOP_INTERVAL);
    //pthread_cancel(capture_thread);
	pthread_exit(NULL); 
}	
}
*/
void scan_capture_thread(void *arg) {
    pcap_t *handle = (pcap_t *)arg;
    struct pcap_pkthdr *header;
    const u_char *packet;
    int timeout_ms = 1000; // Timeout in milliseconds
    int packet_count = 0;

    for (int channel = 1; channel <= MAX_CHANNELS; channel++) {
        if (setChannel(INTERFACE, channel) != 0) {
            fprintf(stderr, "Failed to set channel %d\n", channel);
            dbg_log(MSG_DEBUG,"Failed to set channel %d\n", channel);
            continue;
        }

        printf("Channel %d: Capturing beacons...\n", channel);
        dbg_log(MSG_DEBUG,"Channel %d: Capturing beacons...\n", channel);
        packet_count = 0;

        // Set the timeout for pcap_next_ex
        pcap_set_timeout(handle, timeout_ms);

        // Capture packets until the timeout or a fixed number of packets is reached
        while (pcap_next_ex(handle, &header, &packet) == 1 && packet_count < PACKET_COUNT_PER_CHANNEL) {
            scan_packet_handler(NULL, header, packet); // Process the captured packet
            packet_count++;
        }

        // Wait for a while before hopping to the next channel
        sleep(CHANNEL_HOP_INTERVAL);
    }

    printf("Capture complete.\n");
    dbg_log(MSG_DEBUG,"Capture complete.\n");
    pthread_exit(NULL); 
}

u_int8_t scan_thread_implement(char *filter, char *interface, pcap_t *handle,struct fptr *gfptr) {
    struct bpf_program fp;

	int channel;
	
    // Further processing based on options
    initPacketQueue();

    printf("Interface: %s, Filter: %s\n", interface, filter);
    dbg_log(MSG_DEBUG,"Interface: %s,Filter: %s", interface, filter);
    dbg_log(MSG_DEBUG,"Capturing from Interface: %s", interface);
    printf("Capturing from Interface: %s\n", interface);
    
    //debug_close_file();
	/*for (channel = 1;channel <= MAX_CHANNELS ; channel++) {
    // Set WiFi interface to the current channel
   // printf("enter into the channel selection \n");
    if (setChannel(interface, channel,handle) != 0) {
        printf("%d not setting the channel\n",channel);
        fprintf(stderr, "Failed to set channel %d\n", channel);
        continue;
        //EXIT_FAILURE;
    }
  
	}*/
    pthread_t capture_thread, parse_thread;
     printf("thread creation in process\n");
     dbg_log(MSG_DEBUG,"thread creation in process");
    if (pthread_create(&capture_thread, NULL, (void* (*)(void*))gfptr->bfill_fptr, (void *)handle) != 0 ||
        pthread_create(&parse_thread, NULL, (void* (*)(void*))gfptr->bparse_fptr, (void *)handle) != 0) {
        fprintf(stderr, "Error creating packet capture or parse thread\n");
        dbg_log(MSG_DEBUG,"Error creating packet capture or parse thread");
        pcap_freecode(&fp); // Free the compiled filter
        pcap_close(handle); // Close pcap handle
        pthread_mutex_destroy(&mutex);
        pthread_cond_destroy(&cond);
        return EXIT_FAILURE;
    }
    sleep(CHANNEL_HOP_INTERVAL);
   // pthread_cancel(capture_thread);
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