#include <winsock2.h>  // 필요한 헤더 추가
#include <stdio.h>
#include <pcap.h>

// Ethernet Header Structure
struct ethhdr {
    u_char des[6];//수신자 MAC 주소
	u_char src[6];//송신자 MAC 주소
	short int ptype;//뒤에 나올 패킷의 프로토콜 종류(예:ARP/IP/RARP)
	//IP 헤더가 오는 경우 : 0x0800
	//ARP 헤더가 오는 경우 : 0x0806
	//RARP 헤더가 오는 경우 : 0x0835
};

// IP Header Structure
struct iphdr {
    uint8_t ip_hl;          // Version and Header Length
    uint8_t ip_ver;         // ipv4 , ipv6
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

char* getIpFormat(uint32_t ip_address){

     static char ip_string[16]; // IPv4 주소 문자열은 최대 15글자 (xxx.xxx.xxx.xxx) + null 문자('\0')

    // 32비트 주소를 4개의 옥텟으로 나누어서 문자열로 변환
    sprintf(ip_string, "%u.%u.%u.%u",
        (ip_address >> 24) & 0xFF, // 첫 번째 옥텟
        (ip_address >> 16) & 0xFF, // 두 번째 옥텟
        (ip_address >> 8) & 0xFF,  // 세 번째 옥텟
        ip_address & 0xFF);        // 네 번째 옥텟

    return ip_string;

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

// u_char *user_data: 사용자 정의 데이터로, pcap_loop 함수에서 전달한 사용자 데이터입니다. 이 예시에서는 사용하지 않으므로 무시
// pcap_pkrhdr *pkthdr:  패킷의 헤더 정보를 담고 있는 구조체입니다. 이 구조체에는 캡처된 패킷의 길이, 타임스탬프 등의 정보가 포함
// u_char *packet: 캡처된 패킷의 실제 데이터

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    // Print the entire packet (customize this part based on your needs)
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

    struct ethhdr *eth_header = (struct ethhdr *)packet;
    struct iphdr *ip_header = (struct iphdr *)(packet + 14);
    struct tcphdr *tcp_header = (struct tcphdr *)(packet + 14 + ip_header->ip_hl * 4);
    struct udphdr *udp_header = (struct udphdr *)(packet + ip_header -> ip_hl *4 + sizeof(eth_header));
    // add ...

    
    printf("ip header: %u\n", ip_header->ip_p);
    fprintf(logFile, "ip header: %u\n", ip_header->ip_p);


    // ETHERNET
    printf("\n=============ETHHDR===============\n");
    for(int i =0 ; i<6 ; i++){
        printf("%02X ", eth_header->des[i]);
        printf("%02X ", eth_header->src[i]);
    }
    // printf("%d\n", ntohs(eth_header->ptype)); // ntohs :  big endian -> little endian
    printf("%d\n", eth_header->ptype);
    printf("\n==================================\n");
    printf("\n\n");

    fprintf(logFile,"\n=============ETHHDR===============\n");
    for(int i =0 ; i<6 ; i++){
        fprintf(logFile,"%02X ", eth_header->des[i]);
        fprintf(logFile,"%02X ", eth_header->src[i]);
    }
    fprintf(logFile,"%d\n", eth_header->ptype);
    fprintf(logFile,"\n==================================\n");
    fprintf(logFile,"\n\n");


    // IP
    printf("\n=============IPHDR===============\n");
    printf("ip_hl: %u\n", ip_header->ip_hl);
    printf("ip_ver: %u\n", ip_header->ip_ver);
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
    fprintf(logFile,"ip_hl: %u\n", ip_header->ip_hl);
    fprintf(logFile,"ip_ver: %u\n", ip_header->ip_ver);
    fprintf(logFile,"ip_tos: %u\n", ip_header->ip_tos);
    fprintf(logFile,"ip_len: %u\n", ip_header->ip_len);
    fprintf(logFile,"ip_id: %u\n", ip_header->ip_id);
    fprintf(logFile,"ip_off: %u\n", ip_header->ip_off);
    fprintf(logFile,"ip_ttl: %u\n", ip_header->ip_ttl);
    fprintf(logFile,"ip_p: %u\n", ip_header->ip_p);
    fprintf(logFile,"ip_sum: %u\n", ip_header->ip_sum);
    fprintf(logFile,"ip_src: %s\n", getIpFormat(ip_header->ip_src));
    fprintf(logFile,"ip_dst: %s\n", getIpFormat(ip_header->ip_dst));
    fprintf(logFile,"\n==================================\n");
    fprintf(logFile,"\n\n");


if(ip_header->ip_p)

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

}

int main() {

    // logging
    logFile = fopen("log.txt", "a");
    if(logFile == NULL) {
        fprintf(stderr, "NULL log file.");
        return -1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    
    // Set the network interface you want to capture on
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
    // pcap_close(handle);
    return 0;
}
