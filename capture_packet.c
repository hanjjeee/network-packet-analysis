// #include <winsock2.h> 
#include <stdio.h>
#include <pcap.h>

#define HDR 3592
#define ETHHDR 0
#define IPHDR 1
#define ARPHDR 2
#define RARPHDR 3
#define TCPHDR 4
#define UDPHDR 5

#define IP_PROTOCOL 0x0800
#define ARP_PROTOCOL 0x0866
#define RARP_PROTOCOL 0x0835

// Ethernet Header Structure
struct ethhdr {
    u_char des[6];
	u_char src[6];
	short int ptype;
	//IP 헤더가 오는 경우 : 0x0800
	//ARP 헤더가 오는 경우 : 0x0806
	//RARP 헤더가 오는 경우 : 0x0835
};

// IP Header Structure
struct iphdr {
    uint8_t ip_ver_hl;      // Version and Header Length
    uint8_t ip_tos;         // Type of Service
    uint16_t ip_len;        // Total Length
    uint16_t ip_id;         // Identification
    uint16_t ip_off;        // Fragment Offset
    uint8_t ip_ttl;         // Time to Live
    uint8_t ip_p;           // Protocol
    uint16_t ip_sum;        // Header Checksum
    uint32_t ip_src;        // Source IP Address
    uint32_t ip_dst;        // Destination IP Address
};


// TCP Header Structure
struct tcphdr {
    uint16_t th_sport;      // Source Port
    uint16_t th_dport;      // Destination Port
    uint32_t th_seq;        // Sequence Number
    uint32_t th_ack;        // Acknowledgment Number
    uint8_t th_offx2;       // Data Offset and Reserved bits
    uint8_t th_flags;       // Control Flags
    uint16_t th_win;        // Window
    uint16_t th_sum;        // Checksum
    uint16_t th_urp;        // Urgent Pointer
};

// UDP Headerdr Structure
struct udphdr {
    uint16_t uh_sport;      // Source Port
    uint16_t uh_dport;      // Destination Port
    uint16_t uh_len;        // Length
    uint16_t uh_sum;        // Checksum
};


// log
FILE *logFile = NULL;


// packet
u_char *packet = NULL;

// hdr
struct pcap_pkthdr *pkthdr = NULL;
struct ethhdr *eth_header = NULL;
struct iphdr *ip_header = NULL;
struct tcphdr *tcp_header = NULL;
struct udphdr *udp_header = NULL;

// declare
void printHdr(int type);
char* getETHHdrProtocol(short int type);
char* getIPHdrProtocol(uint8_t ip_p);
char* getIpFormat(uint32_t ip_address);

void packet_handler(u_char *user_data, const struct pcap_pkthdr *packet_header, const u_char *packet_data) {

    pkthdr = packet_header;
    packet = packet_data;
    eth_header = (struct ethhdr *)packet;
    ip_header = (struct iphdr *)(packet + 14);
    tcp_header = (struct tcphdr *)(packet + 34);
    udp_header = (struct udphdr *)(packet + 34);

    printHdr(HDR);
    printHdr(ETHHDR);

    switch(ntohs(eth_header->ptype)){
        case IP_PROTOCOL:
            printHdr(IPHDR);
            break;
        case ARP_PROTOCOL:
            // TODO
            break;
        case RARP_PROTOCOL:
            // TODO
            break;
    }

    // printHdr(TCPHDR);
    // printHdr(UDPHDR);

}

char* getIpFormat(uint32_t ip_address){

    static char ip_string[16];

    // 옥텟 순서 뒤집혀서 맞게 출력되도록 수정.. 
    sprintf(ip_string, "%u.%u.%u.%u",
        (ip_address) & 0xFF, // 첫 번째 옥텟
        (ip_address >> 8) & 0xFF, // 두 번째 옥텟
        (ip_address >> 16) & 0xFF,  // 세 번째 옥텟
        ( ip_address >> 24) & 0xFF);        // 네 번째 옥텟

    return ip_string;

}

char* getETHHdrProtocol(short int type) {
    static char protocol[100];

    switch(type){
        case IP_PROTOCOL: sprintf(protocol, "%s", "IP");
            break;
        case ARP_PROTOCOL: sprintf(protocol, "%s", "ARP");
            break;
        case RARP_PROTOCOL: sprintf(protocol, "%s", "RARP");
            break;
        default: sprintf(protocol, "%x", type);
            break;
    }

    return protocol;
}

char* getIPHdrProtocol(uint8_t ip_p){
    static char protocol[100];

    switch (ip_p){
        case 1: sprintf(protocol, "%s", "ICMP");
        break;
        case 2: sprintf(protocol, "%s", "IGMP (Internet Group Management Protocol), RGMP (Router-port Group Management Protocol)");
        break;
        case 3: sprintf(protocol, "%s", "GGP (Gateway to Gateway Protocol)");
        break;
        case 6: sprintf(protocol, "%s", "TCP");
        break;
        case 15: sprintf(protocol, "%s", "XNET (Cross Net Debugger)");
        break;
        case 16: sprintf(protocol, "%s", "Chaos");
        break;
        case 17: sprintf(protocol, "%s", "UDP");
        break;
        case 18: sprintf(protocol, "%s", "TMux (Transport Multiplexing Protocol)");
        break;
        case 19: sprintf(protocol, "%s", "DCN Measurement Subsystems");
        break;
        case 20: sprintf(protocol, "%s", "HMP (Host Monitoring Protocol)");
        break;
        case 21: sprintf(protocol, "%s", "Packet Radio Measurement");
        break;
        case 22: sprintf(protocol, "%s", "XEROX NS IDP");
        break;
        case 41: sprintf(protocol, "%s", "IPv6 over IPv4");
        break;
        case 43: sprintf(protocol, "%s", "IPv6 Routing header");
        break;
        case 44: sprintf(protocol, "%s", "IPv6 Fragment header");
        break;
        case 47: sprintf(protocol, "%s", "GRE (General Routing Encapsulation)");
        break;
        case 50: sprintf(protocol, "%s", "ESP");
        break;
        case 51: sprintf(protocol, "%s", "AH (Authentication Header)");
        break;
        case 52: sprintf(protocol, "%s", "Integrated Net Layer Security TUBA");
        break;
        case 53: sprintf(protocol, "%s", "IP with Encryption");
        break;
        case 54: sprintf(protocol, "%s", "NARP (NBMA Address Resolution Protocol)");
        break;
        case 55: sprintf(protocol, "%s", "Minimal Encapsulation Protocol");
        break;
        case 56: sprintf(protocol, "%s", "TLSP (Transport Layer Security Protocol using Kryptonet key management)");
        break;
        case 57: sprintf(protocol, "%s", "SKIP");
        break;
        case 58: sprintf(protocol, "%s", "ICMPv6 (Internet Control Message Protocol for IPv6). MLD (Multicast Listener Discovery)");
        break;
        case 89: sprintf(protocol, "%s", "OSPF");
        break;
        default: sprintf(protocol, "%u", ip_p);

    }

    return protocol;
}

void printHdr(int type){
    switch(type) {
        case HDR :
            printf("Packet Captured! Length: %d\n", pkthdr->len);
            printf("\n=============HEADER===============\n");
            printf("Time Stamp: %ld.%06ld\n", pkthdr->ts.tv_sec, pkthdr->ts.tv_usec);
            printf("caplen: %u",pkthdr->caplen);
            printf("len: %u",pkthdr->len);
            printf("\n==================================\n");
            for (int i = 0; i < pkthdr->len; ++i) {
                printf("%02x ", packet[i]); // 패킷의 각 바이트를 16진수로 출력
                if ((i + 1) % 16 == 0) //  각 라인마다 16바이트씩 줄 바꿈을 수행
                    printf("\n");
            }
            printf("\n\n");

            // log
            fprintf(logFile,"Packet Captured! Length: %d\n", pkthdr->len);
            fprintf(logFile,"\n=============HEADER===============\n");
            fprintf(logFile,"Time Stamp: %ld.%06ld\n", pkthdr->ts.tv_sec, pkthdr->ts.tv_usec);
            fprintf(logFile,"caplen: %u",pkthdr->caplen);
            fprintf(logFile,"len: %u",pkthdr->len);
            fprintf(logFile,"\n==================================\n");
            for (int i = 0; i < pkthdr->len; ++i) {
                fprintf(logFile,"%02x ", packet[i]); // 패킷의 각 바이트를 16진수로 출력
                if ((i + 1) % 16 == 0) //  각 라인마다 16바이트씩 줄 바꿈을 수행
                    fprintf(logFile,"\n");
            }
            fprintf(logFile,"\n\n");
            break;

        case ETHHDR : 
            // ETHERNET
            printf("\n=============ETHHDR===============\n");
            printf("ethhdr src: ");
            for(int i =0 ; i<6 ; i++){
                printf("%02X ", eth_header->src[i]);
            }
            printf("\nethhdr dst: ");
            for(int i =0 ; i<6 ; i++){
                printf("%02X ", eth_header->des[i]);
            }
            printf("\n%s\n", getETHHdrProtocol(ntohs(eth_header->ptype)));
            printf("\n==================================\n");
            printf("\n\n");

            fprintf(logFile, "\n=============ETHHDR===============\n");
            fprintf(logFile, "ethhdr src: ");
            for(int i =0 ; i<6 ; i++){
                fprintf(logFile, "%02X ", eth_header->src[i]);
            }
            fprintf(logFile, "\nethhdr dst: ");
            for(int i =0 ; i<6 ; i++){
                fprintf(logFile, "%02X ", eth_header->des[i]);
            }
            fprintf(logFile, "\n%s\n", getETHHdrProtocol(ntohs(eth_header->ptype)));
            fprintf(logFile, "\n==================================\n");
            fprintf(logFile, "\n\n");
            break;
            
        case IPHDR :
            // IP
            printf("\n=============IPHDR===============\n");
            printf("ip_ver: %u\n", ip_header->ip_ver_hl >> 4);
            printf("ip_hl: %u\n", ip_header->ip_ver_hl & 0xf);
            printf("ip_tos: %u\n", ip_header->ip_tos);
            printf("ip_len: %u\n", ip_header->ip_len);
            printf("ip_id: %u\n", ip_header->ip_id);
            printf("ip_off: %u\n", ip_header->ip_off);
            printf("ip_ttl: %u\n", ip_header->ip_ttl);
            printf("ip_p: %s\n", getIPHdrProtocol(ip_header->ip_p));
            printf("ip_sum: %u\n", ip_header->ip_sum);
            printf("ip_src: %s\n", getIpFormat(ip_header->ip_src));
            printf("ip_dst: %s\n", getIpFormat(ip_header->ip_dst));
            printf("\n==================================\n");
            printf("\n\n");

            fprintf(logFile,"\n=============IPHDR===============\n");
            fprintf(logFile,"ip_ver: %u\n", ip_header->ip_ver_hl >> 4);
            fprintf(logFile,"ip_hl: %u\n", ip_header->ip_ver_hl & 0xf);
            fprintf(logFile,"ip_tos: %u\n", ip_header->ip_tos);
            fprintf(logFile,"ip_len: %u\n", ip_header->ip_len);
            fprintf(logFile,"ip_id: %u\n", ip_header->ip_id);
            fprintf(logFile,"ip_off: %u\n", ip_header->ip_off);
            fprintf(logFile,"ip_ttl: %u\n", ip_header->ip_ttl);
            fprintf(logFile,"ip_p: %s\n", getIPHdrProtocol(ip_header->ip_p));
            fprintf(logFile,"ip_sum: %u\n", ip_header->ip_sum);
            fprintf(logFile,"ip_src: %s\n", getIpFormat(ip_header->ip_src));
            fprintf(logFile,"ip_dst: %s\n", getIpFormat(ip_header->ip_dst));
            fprintf(logFile,"\n==================================\n");
            fprintf(logFile,"\n\n");
            break;

        case TCPHDR :
            // TCP
            printf("\n=============TCPHDR===============\n");
            printf("th_sport: %u\n", tcp_header->th_sport);
            printf("th_dport: %u\n", tcp_header->th_dport);
            printf("th_seq: %u\n", tcp_header->th_seq);
            printf("th_ack: %u\n", tcp_header->th_ack);
            printf("th_offx2: %u\n", tcp_header->th_offx2);
            printf("th_flags: %u\n", tcp_header->th_flags);
            printf("th_win: %u\n", tcp_header->th_win);
            printf("th_sum: %u\n", tcp_header->th_sum);
            printf("th_urp: %u\n", tcp_header->th_urp);
            printf("\n==================================\n");
            printf("\n\n");

            fprintf(logFile,"\n=============TCPHDR===============\n");
            fprintf(logFile,"th_sport: %u\n", tcp_header->th_sport);
            fprintf(logFile,"th_dport: %u\n", tcp_header->th_dport);
            fprintf(logFile,"th_seq: %u\n", tcp_header->th_seq);
            fprintf(logFile,"th_ack: %u\n", tcp_header->th_ack);
            fprintf(logFile,"th_offx2: %u\n", tcp_header->th_offx2);
            fprintf(logFile,"th_flags: %u\n", tcp_header->th_flags);
            fprintf(logFile,"th_win: %u\n", tcp_header->th_win);
            fprintf(logFile,"th_sum: %u\n", tcp_header->th_sum);
            fprintf(logFile,"th_urp: %u\n", tcp_header->th_urp);
            fprintf(logFile,"\n==================================\n");
            fprintf(logFile,"\n\n");
            break;

        case UDPHDR :
            // UDP 
            printf("\n=============UDPHDR===============\n");
            printf("uh_sport: %u\n", udp_header->uh_sport);
            printf("uh_dport: %u\n", udp_header->uh_dport);
            printf("uh_len: %u\n", udp_header->uh_len);
            printf("uh_sum: %u\n", udp_header->uh_sum);
            printf("\n==================================\n");
            printf("\n\n");

            fprintf(logFile,"\n=============UDPHDR===============\n");
            fprintf(logFile,"uh_sport: %u\n", udp_header->uh_sport);
            fprintf(logFile,"uh_dport: %u\n", udp_header->uh_dport);
            fprintf(logFile,"uh_len: %u\n", udp_header->uh_len);
            fprintf(logFile,"uh_sum: %u\n", udp_header->uh_sum);
            fprintf(logFile,"\n==================================\n");
            fprintf(logFile,"\n\n");
            break;
        
        default: break;
    }
}

int main() {

    // logging
    logFile = fopen("log.txt", "a");
    if(logFile == NULL) {
        fprintf(stderr, "NULL log file.");
        return -1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    
    // Set the network interface
    char *dev = pcap_lookupdev(errbuf);
    printf("target dev: %s\n", dev);

    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 0, 1000, errbuf);
    printf("handle: %p\n", (void *)handle);

    if (handle == NULL) {
        printf("Couldn't open device %s: %s\n", dev, errbuf);
        fprintf(logFile, "Couldn't open device %s: %s\n", dev, errbuf);
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return 2;
    }

    // Set a BPF filter to capture all packets (customize based on your needs)
    struct bpf_program fp;
    char filter_exp[] = "";
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        printf("Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        fprintf(logFile, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        printf("Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        fprintf(logFile, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }

    // Capture packets indefinitely
    printf("before loop\n");
    pcap_loop(handle, 0, packet_handler, NULL);
    printf("after loop\n");
    pcap_close(handle);
    return 0;
}
