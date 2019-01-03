#ifndef _HEADER_H_
#define _HEADER_H_

#include <pcap.h>
#include <netinet/in.h>
#define ETHER_ADDR_LEN	6

struct sniff_ethernet{
	u_char ether_dhost[ETHER_ADDR_LEN];
	u_char ether_shost[ETHER_ADDR_LEN];
	u_short ether_type;
};

struct sniff_ip{
	u_char ip_vhl;
	u_char ip_tos;
	u_short ip_len;
	u_short ip_id;
	u_short ip_off;
#define IP_RF 0X8000
#define IP_DF 0X4000
#define IP_MF 0X2000
#define IP_OFFMASK 0X1fff
	u_char ip_ttl;
	u_char ip_p;
	u_short ip_sum;
	struct in_addr ip_src,ip_dst;
};

#define IP_HL(ip)	(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)	(((ip)->ip_vhl) >> 4)

typedef unsigned int tcp_seq;

struct sniff_tcp{
	u_short th_sport;
	u_short th_dport;
	tcp_seq th_seq;
	tcp_seq th_ack;
	u_char th_offx2;
#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
	u_char th_flags;
#define TH_FIN 0X01
#define TH_SYN 0X02
#define TH_RST 0X04
#define TH_PUSH 0X08
#define TH_ACK 0X10
#define TH_URG 0X20
#define TH_ECE 0X40
#define TH_CWR 0X80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short th_win;
	u_short th_sum;
	u_short th_urp;
};

#define SIZE_ETHERNET 14

#endif
