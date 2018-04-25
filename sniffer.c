#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <arpa/inet.h>

// define snap length (maximum bytes per packet to capture)
#define SNAP_LEN 1518

// ethernet headers are always exactly 14 bytes
#define SIZE_ETHERNET 14

// Ethernet addresses are 6 bytes
#define ETHER_ADDR_LEN 6

/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};


/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

static void usage(char *argv[])
{
	char *prog = argv[0];
	printf("\nUsage\n%s <filter>\nexample : %s tcp\n", prog, prog);
	exit(1);
}

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	static int count = 1;                   /* packet counter */

	// declare pointers to packet headers
	const struct sniff_ethernet *ethernet;	// The ethernet header
	const struct sniff_ip *ip;	// The IP header

	int size_ip;

	// define ethernet header
	ethernet = (struct sniff_ethernet *)(packet);

	// define/compute ip header offset
	ip = (struct sniff_ip *)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		printf("  * Invalid IP header length : %u bytes\n", size_ip);
		return;
	}

	// print source and destination IP addresses
	printf("    Ethernet source address : %s\n", ether_ntoa((const struct ether_addr *)ethernet->ether_dhost));
	printf("    Ethernet destination address : %s\n", ether_ntoa((const struct ether_addr *)ethernet->ether_shost));
	printf("    From : %s\n", inet_ntoa(ip->ip_src));
	printf("    To   : %s\n", inet_ntoa(ip->ip_dst));
	printf("\nPacket number %d:\n", count);
	count++;
}


int main(int argc, char *argv[])
{
	pcap_t *handle;
	char *dev;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	char *filter_exp;
	bpf_u_int32 mask;
	bpf_u_int32 net;
	struct pcap_pkthdr header;
	const u_char *packet;
	int num_packets = 10;			/* number of packets to capture */

	if (argc < 2) {
		fprintf(stderr, "Not enough arguments");
		usage(argv);
		return(1);
	}

	filter_exp = argv[1];

	// Define the device
	dev = pcap_lookupdev(errbuf);
	if (dev == NULL){
		fprintf(stderr, "Couldn't find the default device : %s", errbuf);
		return(2);
	}
	fprintf(stdout, "Using device : %s\n", dev);

	// Find the properties for the device
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s : %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}

	// Open the session in promiscuous mode
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL ) {
		fprintf(stderr, "Couldn't open device %s : %s\n", dev, errbuf);
		return(2);
	}

	// Compile and apply filter
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse the filter %s : %s\n", filter_exp, errbuf);
		return(2);
	}

	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s : %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}

	// Grab a packet
	packet = pcap_next(handle, &header);
	printf("Jacked a packet with length [%d]\n", header.len);

	// capturing packets using callback
	pcap_loop(handle, num_packets, process_packet, NULL);

	pcap_close(handle);
	fprintf(stdout, "This went well?\n");
	return(0);
}

