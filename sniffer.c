#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>

static void usage(char *argv[])
{
	char *prog = argv[0];
	printf("\nUsage\n%s <filter>\nexample : %s tcp\n", prog, prog);
	exit(1);
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
	pcap_close(handle);
	fprintf(stdout, "This went well?\n");
	return(0);
}

