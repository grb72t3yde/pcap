#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pcap.h>
#include <time.h>
#include <arpa/inet.h>
#include "header.h"

pcap_t *handle;
char* dev;
char errbuf[PCAP_ERRBUF_SIZE];
struct bpf_program fp;
//char filter_exp[] = "port 23";
bpf_u_int32 mask;
bpf_u_int32 net;
struct pcap_pkthdr *header;
const u_char *packet;


const struct sniff_ethernet *ethernet;
const struct sniff_ip *ip;
const struct sniff_tcp *tcp;
const char *payload;

u_int size_ip;
u_int size_tcp;


int main(int argc,char* argv[]){

	char* filename = argv[1];
	char* filter_exp = argv[2];

	char srcip[1024] = {0};
	char dstip[1024] = {0};

	time_t t;
	struct tm* p;
	char time[1024] = {0};

/*	dev = pcap_lookupdev(errbuf);
	if(dev == NULL){
		fprintf(stderr, "Couldn't find default device: %s\n",errbuf);
		return 2;
	}
	printf("Device: %s\n", dev);

	if(pcap_lookupnet(dev, &net, &mask, errbuf) == -1){
		fprintf(stderr,"couldnt get netmask for deivice %s: %s\n",dev,errbuf);
		net = 0;
		mask = 0;
	}*/

	int paccnt = 0;
	int i;



	handle = pcap_open_offline(filename, errbuf);
	if(handle == NULL){
		fprintf(stderr,"Couldn't open device %s: %s\n",dev,errbuf);
		return 2;
	}

	if(pcap_compile(handle, &fp, filter_exp,0,PCAP_NETMASK_UNKNOWN) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n",filter_exp, pcap_geterr(handle));
		return 2;
	}
	if(pcap_setfilter(handle, &fp) == -1){
		fprintf(stderr,"Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return 2;
	}


	while(pcap_next_ex(handle, &header, &packet) >= 0){

		printf("Packet # %i\n", ++paccnt);

		printf("Packet size: %d bytes\n",header->len);

		if(header->len != header->caplen)
			printf("capsize diff from the pacsize: %d bytes\n",header->len);

		ethernet  =  (struct sniff_ethernet*)(packet);
		ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);			
		size_ip = (IP_HL(ip))*4;
	/*	if(size_ip < 20){
			printf(" *Invalid IP header length: %u bytes\n",size_ip);
			return 2;
		}*/
	
		tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
		size_tcp = (TH_OFF(tcp))*4;

/*		if(size_tcp < 20){
			printf(" *Invalid TCP header length: %u bytes\n", size_tcp);
			return 2;
		}*/
		payload = (u_char *)(packet + SIZE_ETHERNET + size_ip +size_tcp);

		printf("src port: %d dest port: %d \n",ntohs(tcp->th_sport), ntohs(tcp->th_dport));

		memset(srcip,0,1024);
		memset(dstip,0,1024);
		strcpy(srcip,inet_ntoa(ip->ip_src));
		strcpy(dstip,inet_ntoa(ip->ip_dst));

		printf("src address: %s des address: %s \n",srcip,dstip);\


		t = (time_t)header->ts.tv_sec;
	//	printf("%ld\n",t);
		p = localtime(&t);

		memset(time,0,1024);

		strftime(time,sizeof(time),"%Y-%m-%d %H:%M:%S", p);

		printf("Time: %s\n",time);
	}



//	printf("jacked a pack with length of [%d]\n",header.len);
//	printf("%u",tcp->th_sport);
	pcap_close(handle);

	return 0;

}
