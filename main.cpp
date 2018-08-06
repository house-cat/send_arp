#include <stdio.h>
#include <pcap.h>
#include <unistd.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/ether.h>

#define ARP 0x08066

typedef struct arp_packet{
	u_int16_t htype;
	u_int16_t ptype;
	u_int8_t hsize;
	u_int8_t psize;
	u_int16_t opcode;
	u_int8_t sender_mac[6];
	u_int8_t sender_ip[4];
	u_int8_t target_mac[6];
	u_int8_t target_ip[4];
}ARP_PACKET;

int main(int argc, char* argv[]){
	if(argc != 4){
		printf("send_arp <interface> <sender_ip> <target_ip>");
		return -1;
	}
	
	char* inf=argv[1];
	struct ether_header ether;
	struct arp_packet arp;


	//Ethernet Header Creation
	

}

