#include <pcap.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define TRUE  1
#define FALSE 0
#define MTU 3000

int get_payload_size(uint8_t protocol, int a /*placeholder for compilation */);

/*
 * @param dest: empty string to hold the IP that is stored in the ip header
 * @param ip_header: Pointer to the byte that starts the ip_header
 * @return: void
 */
void ip_bits_to_str(char* dest, const u_char* ip_header){

	//Zero out the dest IP
	bzero(dest, 64);

	/*
	 * ip arr holds 4 bytes that correspond to IP addr
	 * substr is to be used when concatenating each byte in IPv4 addr to the total ip string
	 */

	uint8_t ip[4];
	char* substr = malloc(sizeof(char) * 8);
 
	/* Grab each bytes of the 4 byte IP addr then convert to string */
	for (int i = 0; i < 4; i++){

		/* get the ith byte of the ip */
		ip[i] = *(ip_header + 16 + i);

		/* Convert each byte to string and concat to dest str */
		snprintf(substr, 4, "%d", ip[i]); 
		strncat(dest, substr, 5);

		if (i != 3){
			strncat(dest, ".", 1);
		}
		
		bzero(substr, strlen(substr));
	}

	free(substr);

}

/* Function called inside callback that does the work */
void process_packet(const u_char* packet, const struct pcap_pkthdr* header){

	struct ether_header* eth_hdr = (struct ether_header*) packet; 

	/* Pointers to start of various headers in the OSI stack */
	const u_char* ip_header;
	const u_char* transport_header;
	const u_char* payload;

	/* Lengths for various parts of packet */
	uint32_t eth_header_len = 14; //Standard
	uint32_t ip_header_len;
	uint32_t transport_header_len;
	uint32_t payload_len;

	/* IP checking IP Dest */
	char dest_ip_str[64];

	/* Check ethernet header is not IP and ignore o.w. process packet */
	if (ntohs(eth_hdr->ether_type) != ETHERTYPE_IP){
		return;
	}

	/* IP Header starts after eth header */
	ip_header = packet + eth_header_len;
	/* IHL (internet header length) is the second(lower 4 bits of first byte in IP header) */
	ip_header_len = ( (*ip_header) & 0x0F) * 4; 

	/* Format bytes of IP dest into a string and put it in dest_ip_str */
	ip_bits_to_str(dest_ip_str, ip_header);
	printf("%s\n", dest_ip_str);
	fflush(stdout);

	/* Get the start of the Transport Layer Packet */
	transport_header = packet + eth_header_len + ip_header_len;
	
	/* Determine packet type */
	const u_char protocol = *(ip_header + 9);



}


/* 
 * Callbacks on pcap_loop to print packet info
 * The three args are the default args for a pcap_t callback
 * args   - Arguments to be passed into the packet_handler
 * hdr    - The packet header
 * packet - The actual packet 
 */
void packet_handler(u_char* args, const struct pcap_pkthdr* hdr, const u_char* packet){
	process_packet(packet, hdr);
	return;
}

int main(){

	pcap_t* handle;                    /* Session Handle */
	struct pcap_pkthdr header;         /* Packet Header */
	const u_char* packet;              /* Actual packet */

	char errbuf[PCAP_ERRBUF_SIZE];

	handle = pcap_open_live("wlo1",     /* Wireless interface */ 
													MTU,        /* Maximum Transmission Unit */
													TRUE,       /* Set promiscuous mode --> capture all packets (packets with any mac address - not just mine) to send to CPU */
													1000,       /* Snapshot length in ms */
													errbuf);    /* Buf to report errors */


	if (handle == NULL){
		fprintf(stderr,"Error: Unable to open device wlo1... %s\n", errbuf);
		return 1;
	}

	/* Loop and callback on packet capture */
	pcap_loop(handle, 0, packet_handler, NULL);

	/* Close the session and exit program */
	pcap_close(handle);
	return 0;
}
