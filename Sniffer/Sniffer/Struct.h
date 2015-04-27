#pragma  once
/*define some protocal*/
#define XNS_IDP 0x0600
#define DLOG 0x0661
#define IP 0x0800
#define X75 0x0801
#define NBS 0x0802
#define ECMA 0x0803
#define Chaosnet 0x0804
#define X25L3 0x0805
#define ARP 0x0806
#define FARP 0x0808
#define RFR 0x6559
#define RARP 0x8035
#define NNIPX 0x8037
#define EtherTalk 0x809B
#define ISSE 0x80D5
#define AARP 0x80F3
#define EAPS 0x8100
#define IPX 0x8137
#define SNMP 0x814C
#define IPv6 0x86DD
#define OAM 0x8809
#define PPP 0x880B
#define GSMP 0x880C
#define MPLSu 0x8847
#define MPLSm 0x8848
#define PPPoEds 0x8863
#define PPPoEss 0x8864
#define LWAPP 0x88BB
#define LLDP 0x88CC
#define EAP 0x8E88
#define LOOPBACK 0x9000
#define VLAN 0x9100

/*define some ip type*/
#define ICMP 1
#define IGMP 2
#define TCP 6
#define UDP 17
#define OSPF 89

/*gotten packet*/
typedef struct packet
{
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
}packet;

/* 4 bytes IP address */ 
typedef struct ip_address 
{ 
	u_char byte1; 
	u_char byte2; 
	u_char byte3; 
	u_char byte4; 
}ip_address; 

/*ethernet header*/
typedef struct ethernet_header
{
	u_char dstmac[6]; //目标mac地址
	u_char srcmac[6]; //源mac地址
	u_short eth_type; //以太网类型
}ethernet_header;

/* IPv4 header */ 
typedef struct ip_header 
{ 
	u_char ihl:4; /* Internet header length (4 bits)*/ 
	u_char ver:4;/*Version (4 bits)*/
	u_char tos; /* Type of service */ 
	u_short tlen; /* Total length */ 
	u_short identification; /* Identification */  
	u_short fo:13; /* Fragment offset (13 bits)*/ 
	u_short flags:3;/*Flags (3 bits) */
	u_char ttl; /* Time to live */ 
	u_char proto; /* Protocol */ 
	u_short crc; /* Header checksum */ 
	ip_address saddr;/* Source address */ 
	ip_address daddr;/* Destination address */ 
	u_int op_pad; /* Option + Padding */ 
}ip_header; 

/* UDP header */ 
typedef struct udp_header 
{ 
	u_short sport; /* Source port */ 
	u_short dport; /* Destination port */ 
	u_short len; /* Datagram length */ 
	u_short crc; /* Checksum */ 
}udp_header; 

typedef struct tcp_header  //20 bytes : default
{
	u_short sport;      //Source port
	u_short dport;      //Destination port
	u_long seqno;       //Sequence no
	u_long ackno;       //Ack no
	u_char reserved_1:4; //保留6位中的4位首部长度
	u_char offset:4;     //tcp头部长度
	u_char flag:6;       //6位标志
	u_char reserved_2:2; //保留6位中的2位
	//FIN - 0x01
	//SYN - 0x02
	//RST - 0x04 
	//PUSH- 0x08
	//ACK- 0x10
	//URG- 0x20
	//ACE- 0x40
	//CWR- 0x80

	u_short win;
	u_short checksum;
	u_short uptr;
}tcp_header;

/*ARP/RARP header*/
typedef struct arp_header   //28 bytes
{
	u_short hrd;       //hardware address space=0x0001
	u_short eth_type;  //Ethernet type ....=0x0800
	u_char maclen;     //Length of mac address=6
	u_char iplen;      //Length of ip addres=4
	u_short opcode;    //Request =1 Reply=2 (highbyte)
	u_char smac[6];    //source mac address
	ip_address saddr;  //Source ip address
	u_char dmac[6];    //Destination mac address
	ip_address daddr;  //Destination ip address
}arp_header,rarp_header;

//ICMP Header
typedef struct icmp_header
{
	u_char type;	  //type
	u_char code;      //code
	u_short chk_sum;  //checksum 16bit
	u_short id; 
	u_short seq; 
	u_long timestamp; 
}icmp_header;

typedef struct igmp_header
{
	u_char type;	  //type
	u_char mrtime;		//Max Response time
	u_short chk_sum;
	u_long mcadd;	//Multicast address
}igmp_header;

typedef struct http_packet
{
	CString request_method;  // 代表请求的方法，如GET、POST、HEAD、OPTIONS、PUT、DELETE和TARCE
	CString request_uri;     // 代表请求的URI，如/sample.jsp
	CString request_Protocol_version;// 代表请求的协议和协议的版本,如HTTP/1.1

	CString request_accept;  // 代表请求的Accept，如 */*
	CString request_referer; // 代表请求的Referer，如 http://www.gucas.ac.cn/gucascn/index.aspx
	CString request_accept_language;  // 代表请求的 Accept-language，如 zh-cn
	CString request_accept_encoding;  // 代表请求的 Accept_encoding，如 gzip、deflate
	CString request_modified_date;  // 代表请求的If-Modified-Since，如 Sun,27 Sep 2009 02:33:14 GMT
	CString request_match;         // 代表请求的If-None-Match，如 "011d3dc1a3fcal:319"
	CString request_user_agent;  // 代表请求的User-Agent，如 Mozilla/4.0(compatible:MSIE 6.0;Windows NT 5.1;SV1;.NET CLR 1.1.4322;.NEt...
	CString request_host;      // 代表请求的Host，如 www.gucas.ac.cn
	CString request_connection;// 代表请求的Connection，如 Keep-Alive
	CString request_cookie;    // 代表请求的Cookie，如 ASP.NET_SessionId=hw15u245x23tqr45ef4jaiqc

	CString request_entity_boy;// 代表请求的实体主体
	//===================================================================================
	CString respond_Protocol_version; // 代表响应协议和协议的版本,如HTTP/1.1
	CString respond_status;         // 代表响应状态代码，如200
	CString respond_description;  // 代表响应状态代码的文本描述，如OK

	CString respond_content_type; // 代表响应内容的类型，如text/html
	CString respond_charset;      // 代表响应字符，如UTF-8
	CString respond_content_length; // 代表响应内容的长度，如9
	CString respond_connection; // 代表响应连接状态，如close
	CString respond_Cache_Control; // 代表响应连接状态，如private
	CString respond_X_Powered_By; // 代表响应连接状态，如ASP.NET
	CString respond_X_AspNet_Version; // 代表响应连接状态，如1.1.4322
	CString respond_Set_Cookie; // 代表响应连接状态，如ASP.NET_SessionId=w0qojdwi0welb4550lafq55;path=/

	CString respond_date;       // 代表响应日期，如fri,23 Oct 2009 11:15:31 GMT
	CString respond_Etag;       // 代表无修改，如"Ocld8a8cc91:319"
	CString respond_server;     // 代表响应服务，如lighttpd

	CString respond_entity_boy; // 代表响应实体主体，如IMOld(8);
}http_packet;
