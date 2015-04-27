// SnifferDlg.h : 头文件
//

#pragma once
#include "afxwin.h"
#include "afxcmn.h"
#include "MyPcap.h"
#include "FilterDlg.h"
#include "ChartDlg.h"
//#include "Struct.h"


static UINT CapThread(LPVOID lpParameter);
static UINT ReadDumpThread(LPVOID lpParameter);
static UINT LoadThread(LPVOID lpParameter);

//static CRITICAL_SECTION ReadThreadCS;
// DWORD WINAPI CapThread(LPVOID);
// DWORD dwThread;
/*static HWND hmainDialog;*/
/*static int num;*/

static wchar_t FilePath[256];//程序运行路径
static CString CapFilePath;//临时抓包文件路径
static CString filterstr;

/*#define WM_PACKET_IN (WM_USER+85)*/
// CSnifferDlg 对话框
class CSnifferDlg : public CDialog
{
// 构造
public:
	CSnifferDlg(CWnd* pParent = NULL);	// 标准构造函数

// 对话框数据
	enum { IDD = IDD_SNIFFER_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	CComboBox m_devComboBox;
	pcap_if_t *alldevs;
	pcap_if_t *d;
	CListCtrl m_List;
	afx_msg void OnSize(UINT nType, int cx, int cy);//no use
/*	afx_msg LRESULT OnPacketIn(WPARAM wParam, LPARAM lParam);*/
	CButton m_saveBtn;
	afx_msg void OnBnClickedButton1();
	CWinThread *hCapThread;
	CMyPcap myPcap;
	afx_msg void OnBnClickedButton2();
	BOOL capStatus;
	afx_msg void OnClose();
	void ShowPacketOnList(packet* p);//packet info on listctrl
	static void GetEthernetType(ethernet_header * e,char *typestr);//获得以太网类型
	static void GetIPv4Type(ip_header* ih, char* pt);//IP类型

	afx_msg void OnNMClickList2(NMHDR *pNMHDR, LRESULT *pResult);
	//CString m_EditPacket;
	CEdit m_packetData;
	CFont   m_Font;
	static BOOL IsHttp(struct pcap_pkthdr *header,const u_char* p);//no use
	CTreeCtrl m_InfoTree;
	//将包信息输出到edit上
	static CString PackToEdit(struct pcap_pkthdr* header, const u_char* pkt_data);
	static void DecToBinary(int n, char* ch);
	//以下输出分析树
	static void ShowIPInfo(const u_char* pkt_data,CSnifferDlg* mDlg);
	static void ShowArpInfo(arp_header* arpheader, CSnifferDlg* mDlg);
	static void ShowUDPInfo(udp_header* udpheader, CSnifferDlg* mDlg);
	static void ShowICMPInfo(icmp_header* icmpheader, CSnifferDlg* mDlg);
	static void ShowIGMPInfo(igmp_header* igmpheader, CSnifferDlg* mDlg);
	static void ShowTCPInfo(tcp_header* tcpheader, CSnifferDlg* mDlg, u_short tcpdataLen);
	CMenu m_Menu;
	afx_msg void OnCaptureStart();
	afx_msg void OnCaptureStop();
	afx_msg void OnCaptureInterface();
	CFilterDlg filter;
	//static char* filterstr;
	afx_msg void OnBnClickedButton5();
	afx_msg void OnBnClickedButton4();
	afx_msg void OnBnClickedButton6();
//	afx_msg void OnTimer(UINT_PTR nIDEvent);
//	afx_msg void OnTimer(UINT_PTR nIDEvent);
	afx_msg void OnBnClickedButton3();
};
