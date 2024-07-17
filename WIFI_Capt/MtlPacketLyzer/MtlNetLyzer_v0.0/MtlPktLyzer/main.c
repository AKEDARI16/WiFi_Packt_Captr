#include "MtlPktLyzer.h"

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t cond = PTHREAD_COND_INITIALIZER;

struct pkt 
void (*bfill_fptr)(void *);
void (*bparse_fptr)(void *);

void UsageHandler(char *str) {
	printf("Usage: %s [interface] [-h] [-c SSID PWD ] [-p filter] [-s] [other_options]\n", str);
	// Add help message explanations for each option here
	printf("interface: Network interface to monitor.\n");
	printf("-h: Display this help message.\n");
	printf("-c: connect to specific AP/ Router.\n");
	printf("-p: capture packets and Specify a filter string.\n");
	printf("-s: Scan for AP's/Wifi routers around you.\n");
	// Add more
}

int main(int argc, char *argv[]) {
    // Initialization
    int opt;
    char *interface = NULL;
	//char *ssid = NULL;
	//char *password = NULL;
    char *filter = "";
	struct bpf_program fp;  // Compiled filter
	bpf_u_int32 net;

    if (pthread_mutex_init(&mutex, NULL) != 0 || pthread_cond_init(&cond, NULL) != 0) {
        fprintf(stderr, "Mutex or condition variable initialization failed\n");
        return EXIT_FAILURE;
    }

    // Parse command-line options
    if (argc < 2 || argc > 4) {
        UsageHandler(argv[0]);
        return EXIT_SUCCESS;
    }

    // Check if required arguments are provided
    if (optind < argc) {
        interface = argv[optind++];
    } else {
        fprintf(stderr, "Error: Missing interface\n");
        fprintf(stderr, "Usage: %s <interface> -p <filter>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

	printf("optind: %d, argc:%d",optind,argc);
    // Open Wi-Fi device for packet capture
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(interface, 8024, 1, 100, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", interface, errbuf);
        return EXIT_FAILURE;
    }


	printf("opt: %c", opt);
	while ((opt = getopt(argc, argv, "c:p:hs:w")) != -1) {
        switch (opt) {
		case 'c':
		
			/* Assign corresponding functions to function pointers */
		    	bfill_fptr = &connect_capture_thread;
			bparse_fptr = &connect_parse_thread;

			char *filter = "arp or udp or (icmp6 and icmp6[0] == 128) or (ip and (udp or icmp)) or ip6";
			if (pcap_compile(handle, &fp, filter, 0, PCAP_NETMASK_UNKNOWN) == -1) {
				fprintf(stderr, "Couldn't parse filter %s: %s\n", filter, pcap_geterr(handle));
				return 1;
			}

			// Set the filter
			if (pcap_setfilter(handle, &fp) == -1) {
				fprintf(stderr, "Couldn't install filter %s: %s\n", filter, pcap_geterr(handle));
				return 1;
			}
			connect_thread_implement(filter, argv,interface, handle);
			printf("call connect thread implementation function");
			break;
		case 'p':
		    	/* Assign corresponding functions to function pointers */
		    	bfill_fptr = &packet_capture_thread;
			bparse_fptr = &packet_parse_thread;

			filter = optarg;
			printf("filter: %s\n",filter);
			if (pcap_compile(handle, &fp, filter, 0, PCAP_NETMASK_UNKNOWN) == -1) {
				fprintf(stderr, "Couldn't parse filter %s: %s\n", filter, pcap_geterr(handle));
				exit(EXIT_FAILURE);
			}

			if (pcap_setfilter(handle, &fp) == -1) {
				fprintf(stderr, "Couldn't install filter %s: %s\n", filter, pcap_geterr(handle));
				exit(EXIT_FAILURE);
			}
			capture_thread_implement(filter, argv,interface, handle);
			break;
		case 's':
			/* Assign corresponding functions to function pointers */
			bfill_fptr = &scan_capture_thread;
			bparse_fptr = &scan_parse_thread;
			printf("call scan thread implementation function\n");
			scan_thread_implement(filter, argv,interface, handle);
			break;
		case 'w':
			bfill_fptr = &handshake_capture_thread;
			bparse_fptr = &handshake_parse_thread;
			char filter_exp[] = "ether proto 0x888e"; // Filter expression for EAPOL frames
			if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
				fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
				return 1;
			}
			if (pcap_setfilter(handle, &fp) == -1) {
				fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
				return 1;
			}
			handshake_thread_implement(filter_exp, argv,interface, handle);
			break;
		case 'h':
			UsageHandler(argv[0]);
			return EXIT_SUCCESS;
		default:
			printf("opt: %c", opt);
			printf("calling default");
			UsageHandler(argv[0]);
			exit(EXIT_FAILURE);
		}	
	}
    return 0;
}
