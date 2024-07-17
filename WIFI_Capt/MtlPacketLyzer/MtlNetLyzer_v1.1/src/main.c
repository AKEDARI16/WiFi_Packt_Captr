#include "MtlPktLyzer.h"
#include "func_dec.h"
#include "dbgprint.h" 

int log_level = MSG_MSGDUMP;
int debug_timestamp = 1;
int debug_syslog = 0;
const char *debug_file_path = "./log/cap_debug.log";
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t cond = PTHREAD_COND_INITIALIZER;

 void *(*bfill_d_fptr)(void *);
 void *(*bparse_d_fptr)(void *);


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

void exit_handler()
{
	pid_t iPid = getpid(); /* Process gets its id.*/
	debug_close_file();
	kill(iPid, SIGINT); 
	exit(0);

}

int main(int argc, char *argv[]) {
    // Initialization
    int opt;
    char *interface = NULL;
    char *filter = " ";
	char filter_exp1[1000];
	struct bpf_program fp;  // Compiled filter
	u_int8_t thread_creation;
  //  gfptr *gfptr
 	struct fptr *gfptr = malloc(sizeof(gfptr));
 	debug_open_file(debug_file_path);

	signal(SIGINT,exit_handler);

    if (pthread_mutex_init(&mutex, NULL) != 0 || pthread_cond_init(&cond, NULL) != 0) {
        fprintf(stderr, "Mutex or condition variable initialization failed\n");
		dbg_log(MSG_DEBUG,"Mutex or condition variable initialization failed\n");
        return EXIT_FAILURE;
    }

    // Parse command-line options
    if (argc < 2 || argc > 4) {
        UsageHandler(argv[0]);
        return EXIT_SUCCESS;
    }

    // Check if required arguments are provided
	printf("glob");
	dbg_log(MSG_DEBUG,"glob");
    if (optind < argc) {
        interface = argv[optind++];
    } else {
      //  fprintf(stderr, "Error: Missing interface\n");
	  dbg_log(MSG_DEBUG,"Error: Missing interface");
	  dbg_log(MSG_DEBUG,"Usage: %s <interface> -p <filter>\n", argv[0]);
        //fprintf(stderr, "Usage: %s <interface> -p <filter>\n", argv[0]);

        exit(EXIT_FAILURE);
    }

	printf("optind: %d, argc:%d",optind,argc);
	dbg_log(MSG_DEBUG,"optind: %d, argc:%d",optind,argc);
	dbg_log(MSG_DEBUG,"%s: Logging in  %s\n",__func__, "DEBUG");
    dbg_log(MSG_ERROR,"%s: Logging in  %s\n",__func__, "ERROR");
    dbg_log(MSG_INFO,"%s: Logging in  %s\n",__func__, "INFO");
    dbg_log(MSG_WARNING,"%s: Logging in  %s\n",__func__, "WARNING");
    dbg_log(MSG_MSGDUMP,"%s: Logging in  %s \n",__func__, "DUMP");

	//debug_close_file();
    // Open Wi-Fi device for packet capture
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(interface, 8024, 1, 100, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", interface, errbuf);
		dbg_log(MSG_DEBUG,"Couldn't open device %s: %s\n", interface, errbuf);

        return EXIT_FAILURE;
    }


	//printf("opt: %c", opt);
	while ((opt = getopt(argc, argv, "c:p:hs:w")) != -1) {
        switch (opt) {
		case 'c':
		
			/* Assign corresponding functions to function pointers */
		    gfptr->bfill_fptr = &connect_capture_thread;
			gfptr->bparse_fptr = &connect_parse_thread;

			//char *filter = "arp or udp or (icmp6 and icmp6[0] == 128) or (ip and (udp or icmp)) or ip6";
			char *filter = "";
			if (pcap_compile(handle, &fp, filter, 0, PCAP_NETMASK_UNKNOWN) == -1) {
				fprintf(stderr, "Couldn't parse filter %s: %s\n", filter, pcap_geterr(handle));
				dbg_log(MSG_DEBUG,"Couldn't parse filter %s: %s\n", filter, pcap_geterr(handle));
				return 1;
			}

			// Set the filter
			if (pcap_setfilter(handle, &fp) == -1) {
				fprintf(stderr, "Couldn't install filter %s: %s\n", filter, pcap_geterr(handle));
				dbg_log(MSG_DEBUG,"Couldn't install filter %s: %s\n", filter, pcap_geterr(handle));
				return 1;
			}
			thread_creation = connect_thread_implement(filter, interface, handle, gfptr);
			printf("call connect thread implementation function");
			dbg_log(MSG_DEBUG,"call connect thread implementation function");
			break;
		case 'p':
		   
			/* Assign corresponding functions to function pointers */
		    gfptr->bfill_fptr = &packet_capture_thread;
			gfptr->bparse_fptr = &packet_parse_thread;

			//filter = optarg;
			filter = "";
			printf("filter: %s\n",filter);
			dbg_log(MSG_DEBUG,"filter: %s\n",filter);
			if (pcap_compile(handle, &fp, filter, 0, PCAP_NETMASK_UNKNOWN) == -1) {
				fprintf(stderr, "Couldn't parse filter %s: %s\n", filter, pcap_geterr(handle));
				dbg_log(MSG_DEBUG,"Couldn't parse filter %s: %s\n", filter, pcap_geterr(handle));
				exit(EXIT_FAILURE);
			}

			if (pcap_setfilter(handle, &fp) == -1) {
				fprintf(stderr, "Couldn't install filter %s: %s\n", filter, pcap_geterr(handle));
				dbg_log(MSG_DEBUG,"Couldn't install filter %s: %s\n", filter, pcap_geterr(handle));
				exit(EXIT_FAILURE);
			}
			thread_creation = capture_thread_implement(filter, interface, handle, gfptr);
			break;
		case 's':
			
			/* Assign corresponding functions to function pointers */
			gfptr->bfill_fptr = &scan_capture_thread;
			gfptr->bparse_fptr = &scan_parse_thread;
			//char *filter_exp = "arp or udp or (icmp6 and icmp6[0] == 128) or (ip and (udp or icmp)) or ip6";
			char *filter_exp = "";

			if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
				fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
				dbg_log(MSG_DEBUG,"Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
				return 1;
			}

			// Set the filter
			if (pcap_setfilter(handle, &fp) == -1) {
				fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
				dbg_log(MSG_DEBUG,"Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
				return 1;
			}
			
			thread_creation = scan_thread_implement(filter_exp, interface, handle, gfptr);
			break;
			
		case 'w':
			/*gfptr.bfill_fptr = &handshake_capture_thread;
			bparse_fptr = &handshake_parse_thread;*/
			strcpy(filter_exp1, "ether proto 0x888e");
			//char *filter_exp1 = "ether proto 0x888e"; // Filter expressi(filter_exp1, "ether proto 0x888e")on for EAPOL frames
			if (pcap_compile(handle, &fp, filter_exp1, 0, PCAP_NETMASK_UNKNOWN) == -1) {
				fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp1, pcap_geterr(handle));
				dbg_log(MSG_DEBUG,"Couldn't parse filter %s: %s\n", filter_exp1, pcap_geterr(handle));
				return 1;
			}
			if (pcap_setfilter(handle, &fp) == -1) {
				fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp1, pcap_geterr(handle));
				dbg_log(MSG_DEBUG,"Couldn't install filter %s: %s\n", filter_exp1, pcap_geterr(handle));
				return 1;
			}
			handshake_implement(filter_exp1, interface, handle);
			break;
		case 'h':
			UsageHandler(argv[0]);
			return EXIT_SUCCESS;

		default:
			printf("opt: %c", opt);
			dbg_log(MSG_DEBUG,"opt: %c", opt);
			printf("calling default");
			dbg_log(MSG_DEBUG,"calling default");
			UsageHandler(argv[0]);
			exit(EXIT_FAILURE);
		}	
	}
	exit_handler();
    return 0;

}
