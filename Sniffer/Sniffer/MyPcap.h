#pragma once
#include "pcap.h"
#include "Struct.h"
//#include "SnifferDlg.h"



//#define WM_UPDATE_LIST (WM_USER+85)

class CMyPcap
{
public:
	CMyPcap(void);
	~CMyPcap(void);
	//  取得所有的网卡设备
	pcap_if_t* GetAllAdapter(void);
	

public:
	//pcap_if_t* devnow;
	/*pcap_dumper_t *dumpfile;*/
	
	static int SavePacket(struct pcap_pkthdr *header,const u_char *pkt_data,pcap_dumper_t* d);
};
