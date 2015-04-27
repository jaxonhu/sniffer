#include "StdAfx.h"
#include "MyPcap.h"

CMyPcap::CMyPcap(void)
{

}

CMyPcap::~CMyPcap(void)
{
}

//  取得所有的网卡设备
pcap_if_t* CMyPcap::GetAllAdapter(void)
{
	pcap_if_t *alldev;
	char errbuf[PCAP_ERRBUF_SIZE+1];
	if(pcap_findalldevs_ex(PCAP_SRC_IF_STRING,NULL,&alldev,errbuf)==-1)
	{
		CString errstring;
		errstring.Format(_T("Error in pcap_findalldevs_ex,errinfo:%s"),errbuf);
		AfxMessageBox(errstring);
		return NULL;
	}
	else 
		if(NULL==alldev)
		{
			AfxMessageBox(_T("No interfaces found! Make sure WinPcap 4.1.2 is installed..."));
			ShellExecute(NULL, NULL, _T("http://www.winpcap.org/install/default.htm"), NULL, NULL, SW_SHOWNORMAL);
			return NULL;
		}
		else
			return alldev;
}




int CMyPcap::SavePacket(struct pcap_pkthdr *header,const u_char *pkt_data,pcap_dumper_t* d)
{
	pcap_dump((u_char*)d,header,pkt_data);
	pcap_dump_flush(d);
	return 0;
}
