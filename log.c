#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <errno.h>

#define LOG_FILE "log.txt"

// Define a struct for the DHCP packet (IGNORE FOR NOW. DHCP HANDLER NOT WORKING.)
typedef struct {
    uint8_t op; // Message op code / message type
    uint8_t htype; // Hardware address type
    uint8_t hlen; // Hardware address length
    uint8_t hops; 
    uint32_t xid; 
    uint16_t secs; // Seconds since client started looking
    uint16_t flags; 
    uint32_t ciaddr; // Client IP address (if already in use)
    uint32_t yiaddr; // 'Your' IP address
    uint32_t siaddr; // Server IP address
    uint32_t giaddr; // Gateway IP address
    uint8_t chaddr [16]; // Client hardware address
    uint8_t sname [64]; // Server host name
    uint8_t file [128]; // Boot file name
    uint8_t options [64]; // Optional parameters
} dhcp_packet;

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void dhcp_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet);

int main(int argc, char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct bpf_program fp;
    char filter_exp[] = "arp";
    bpf_u_int32 net;
    bpf_u_int32 mask;
    struct pcap_pkthdr header;
    const u_char *packet;
    time_t lease_expiry;
    struct timeval tv;
    struct tm *tm_info;
    FILE *log_file;
    int reset_log = 0;
    char interface[] = "enp0s8";

    // Open the network interface for capturing packets
    handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open interface: %s\n", errbuf);
        exit(1);
    }

    // Compile and apply the ARP filter
    if (pcap_lookupnet(interface, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for interface: %s\n", errbuf);
        net = 0;
        mask = 0;
    }
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter: %s\n", pcap_geterr(handle));
        exit(1);
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter: %s\n", pcap_geterr(handle));
        exit(1);
    }

    // Open the log file for writing
    log_file = fopen(LOG_FILE, "w");
    if (log_file == NULL) {
        fprintf(stderr, "Couldn't open log file: %s\n", strerror(errno));
        exit(1);
    }

    // Start capturing packets and processing them
    pcap_loop(handle, -1, process_packet, (u_char *)log_file);

    // Close the log file and the packet capture handle
    fclose(log_file);
    pcap_close(handle);

    return 0;
}

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
    // Parse the packet data
    struct ether_header *eth_header;
    eth_header = (struct ether_header *) buffer;

    // Looks only for ARP packets in the packet data
    if (ntohs(eth_header->ether_type) == ETHERTYPE_ARP)
    {
        struct timeval tv;
        gettimeofday(&tv, NULL);
        time_t nowtime = tv.tv_sec;
        struct tm *nowtm = localtime(&nowtime);

        // Parse the ARP header
        struct ether_arp *arp_header;
        arp_header = (struct ether_arp *)(buffer + sizeof(struct ether_header));

        // Convert the IP addresses to strings
        char sender_ip[INET_ADDRSTRLEN];
        char target_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, arp_header->arp_spa, sender_ip, sizeof(sender_ip));
        inet_ntop(AF_INET, arp_header->arp_tpa, target_ip, sizeof(target_ip));

        // Convert the MAC addresses to strings
        char sender_mac[18];
        char target_mac[18];
        snprintf(sender_mac, sizeof(sender_mac), "%02x:%02x:%02x:%02x:%02x:%02x", arp_header->arp_sha[0], arp_header->arp_sha[1], arp_header->arp_sha[2], arp_header->arp_sha[3], arp_header->arp_sha[4], arp_header->arp_sha[5]);
        snprintf(target_mac, sizeof(target_mac), "%02x:%02x:%02x:%02x:%02x:%02x", arp_header->arp_tha[0], arp_header->arp_tha[1], arp_header->arp_tha[2], arp_header->arp_tha[3], arp_header->arp_tha[4], arp_header->arp_tha[5]);

        // Open the log file for writing
        FILE *logfile;
        logfile = fopen("log.txt", "a");
        if (logfile == NULL) {
            printf("Unable to open log file.\n");
            return;
        }

        // Write the ARP data to the log file
        fprintf(logfile, "%04d-%02d-%02d %02d:%02d:%02d Sender IP: %s Sender MAC: %s Target IP: %s Target MAC: %s\n", 
            nowtm->tm_year + 1900, nowtm->tm_mon + 1, nowtm->tm_mday, nowtm->tm_hour, nowtm->tm_min, nowtm->tm_sec,
            sender_ip, sender_mac, target_ip, target_mac);

        // Close the log file
        fclose(logfile);
    }
}
