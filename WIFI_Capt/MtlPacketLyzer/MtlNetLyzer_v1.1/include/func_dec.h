void connect_capture_thread(void *);
void connect_parse_thread();
u_int8_t connect_thread_implement(char *, char *interface, pcap_t *,struct fptr *gfptr);

void packet_capture_thread(void *);
void packet_parse_thread();
u_int8_t capture_thread_implement(char *, char *interface, pcap_t *,struct fptr *gfptr);
//extern void capture_thread_implement(char *filter, char *interface, pcap_t *handle);

void scan_capture_thread(void *);
void scan_parse_thread(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
u_int8_t scan_thread_implement(char *, char *interface, pcap_t *,struct fptr *gfptr);
//extern void scan_thread_implement(char *, char *interface, pcap_t *);

void handshake_implement(char *, char *interface, pcap_t *);


extern void initPacketQueue();

extern int isQueueEmpty();
extern int isQueueFull();

extern void enqueuePacket(const struct pcap_pkthdr *header, const u_char *packet);

extern struct PacketNode dequeuePacket();