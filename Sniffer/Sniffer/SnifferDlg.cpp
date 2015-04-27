// SnifferDlg.cpp : 实现文件
//

#include "stdafx.h"
#include "Sniffer.h"
#include "SnifferDlg.h"


#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialog
{
public:
	CAboutDlg();

// 对话框数据
	enum { IDD = IDD_ABOUTBOX };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialog(CAboutDlg::IDD)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialog)
END_MESSAGE_MAP()


// CSnifferDlg 对话框




CSnifferDlg::CSnifferDlg(CWnd* pParent /*=NULL*/)
	: CDialog(CSnifferDlg::IDD, pParent)
	/*, m_EditPacket(_T(""))*/
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CSnifferDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_COMBO1, m_devComboBox);
	DDX_Control(pDX, IDC_LIST2, m_List);
	DDX_Control(pDX, IDC_BUTTON3, m_saveBtn);
	/*DDX_Text(pDX, IDC_EDIT1, m_EditPacket);*/
	DDX_Control(pDX, IDC_EDIT1, m_packetData);
	DDX_Control(pDX, IDC_TREE1, m_InfoTree);
}

BEGIN_MESSAGE_MAP(CSnifferDlg, CDialog)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	//}}AFX_MSG_MAP
	ON_WM_SIZE()
	ON_BN_CLICKED(IDC_BUTTON1, &CSnifferDlg::OnBnClickedButton1)
/*	ON_MESSAGE(WM_PACKET_IN, OnPacketIn)*/
	ON_BN_CLICKED(IDC_BUTTON2, &CSnifferDlg::OnBnClickedButton2)
	ON_WM_CLOSE()
//	ON_NOTIFY(HDN_ITEMCLICK, 0, &CSnifferDlg::OnHdnItemclickList2)
//	ON_NOTIFY(LVN_ITEMCHANGED, IDC_LIST2, &CSnifferDlg::OnLvnItemchangedList2)
//ON_NOTIFY(LVN_ITEMACTIVATE, IDC_LIST2, &CSnifferDlg::OnLvnItemActivateList2)
ON_NOTIFY(NM_CLICK, IDC_LIST2, &CSnifferDlg::OnNMClickList2)
ON_COMMAND(ID_CAPTURE_START, &CSnifferDlg::OnCaptureStart)
ON_COMMAND(ID_CAPTURE_STOP, &CSnifferDlg::OnCaptureStop)
ON_COMMAND(ID_CAPTURE_INTERFACE, &CSnifferDlg::OnCaptureInterface)
ON_BN_CLICKED(IDC_BUTTON5, &CSnifferDlg::OnBnClickedButton5)
ON_BN_CLICKED(IDC_BUTTON4, &CSnifferDlg::OnBnClickedButton4)
ON_BN_CLICKED(IDC_BUTTON6, &CSnifferDlg::OnBnClickedButton6)
//ON_WM_TIMER()
//ON_WM_TIMER()
ON_BN_CLICKED(IDC_BUTTON3, &CSnifferDlg::OnBnClickedButton3)
END_MESSAGE_MAP()


// CSnifferDlg 消息处理程序

BOOL CSnifferDlg::OnInitDialog()
{
	CDialog::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		CString strAboutMenu;
		strAboutMenu.LoadString(IDS_ABOUTBOX);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 设置此对话框的图标。当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码
// 	m_Menu.LoadMenu(IDR_MENU1);
// 	this->SetMenu(&m_Menu);
	
	//SetTimer(1,1000,NULL);
//	tcpnum=udpnum=icmpnum=arpnum=igmpnum=0;
	GetDlgItem(IDC_BUTTON2)->EnableWindow(FALSE);//按钮属性
	GetDlgItem(IDC_BUTTON6)->EnableWindow(FALSE);
	//SetTimer(1,1000,NULL);
	//设置ListCtrl
	m_List.SetExtendedStyle( LVS_EX_GRIDLINES | LVS_EX_FULLROWSELECT | LVS_EX_HEADERDRAGDROP);
	m_List.InsertColumn(0,_T("Num"),LVCFMT_LEFT,50);
	m_List.InsertColumn(1,_T("Time"),LVCFMT_LEFT,90);
	m_List.InsertColumn(2,_T("Source"),LVCFMT_LEFT,120);
	m_List.InsertColumn(3,_T("Destination"),LVCFMT_LEFT,120);
	m_List.InsertColumn(4,_T("Protocol"),LVCFMT_LEFT,80);
	m_List.InsertColumn(5,_T("Length"),LVCFMT_LEFT,90);
	m_List.InsertColumn(6,_T("Info"),LVCFMT_LEFT,300);
	// 获得所有网卡设备
	alldevs=myPcap.GetAllAdapter();
	for(d=alldevs;d;d=d->next)
	{
		//m_devComboBox.AddString(CString(d->description));
		m_devComboBox.InsertString(m_devComboBox.GetCount (),CString(d->description));
	}
	pcap_freealldevs(d);
	InitializeCriticalSection(&CapThreadCS);//no use
	/*InitializeCriticalSection(&ReadThreadCS);*/
// 	GetDlgItem(IDC_BUTTON2)->EnableWindow(FALSE);//Stop按钮设置为禁用
// 	GetMenu()->GetSubMenu(1)->EnableMenuItem(ID_CAPTURE_STOP, MF_BYCOMMAND|MF_DISABLED|MF_GRAYED);
/*	hmainDialog=this->GetSafeHwnd();*/
	capStatus=FALSE;
// 	GetModuleFileName(0,FilePath,255);
// 	CapFilePath=FilePath;
// 	CapFilePath=CapFilePath.Left(CapFilePath.ReverseFind('\\'));
// 	CapFilePath+="\\tmpData.CAP";//文档存储设置 
	m_Font.CreateFont(15,0,0,0,FW_NORMAL,FALSE,FALSE,0,DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,DEFAULT_QUALITY,FF_SWISS|DEFAULT_PITCH,_T("DejaVu Sans Mono"));  
 	m_packetData.SetFont(&m_Font);
 	m_InfoTree.SetFont(&m_Font);
	m_List.SetFont(&m_Font);
	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CSnifferDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialog::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CSnifferDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialog::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CSnifferDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}


void CSnifferDlg::OnSize(UINT nType, int cx, int cy)
{

	CDialog::OnSize(nType, cx, cy);

	// TODO: Add your message handler code here
// 	CRect sz;
// 	GetClientRect(sz);
	//m_saveBtn.SetWindowPos(CWnd*(this),20,20,20,20,SWP_NOSIZE|SWP_NOZORDER);
}

void CSnifferDlg::OnBnClickedButton1()
{
	// TODO: Add your control notification handler code here
	//num=0;
	GetModuleFileName(0,FilePath,255);
	CapFilePath=FilePath;
	CapFilePath=CapFilePath.Left(CapFilePath.ReverseFind('\\'));
	CapFilePath+="\\tmpData.CAP";//文档存储设置 
	int devnum=m_devComboBox.GetCurSel();
	if(CB_ERR==devnum)
	{
		AfxMessageBox(_T("Please select an adapter!"));
		return;
	}
	int i;
	//定位网络设备
	for(d=alldevs,i=0;i<devnum;d=d->next,i++);
	//myPcap.devnow=d;
	//AfxMessageBox(CString(d->description));
	m_List.DeleteAllItems();
	m_InfoTree.DeleteAllItems();
	this->SetDlgItemText(IDC_EDIT1,CString(""));
	GetDlgItem(IDC_BUTTON1)->EnableWindow(FALSE);
	GetDlgItem(IDC_BUTTON2)->EnableWindow(TRUE);
	GetDlgItem(IDC_BUTTON5)->EnableWindow(FALSE);
	GetDlgItem(IDC_BUTTON6)->EnableWindow(TRUE);
// 	GetMenu()->GetSubMenu(1)->EnableMenuItem(ID_CAPTURE_START, MF_BYCOMMAND|MF_DISABLED|MF_GRAYED);
// 	GetMenu()->GetSubMenu(1)->EnableMenuItem(ID_CAPTURE_STOP, MF_BYCOMMAND|MF_ENABLED);
	capStatus=TRUE;
	hCapThread=AfxBeginThread(CapThread,(LPVOID)d);
/*	hCapThread = CreateThread(NULL,0,CapThread,(LPVOID)d,0,&dwThread);*/
	
}

// LRESULT CSnifferDlg::OnPacketIn(WPARAM wParam, LPARAM lParam)
// {
// /*	++num;*/
// 	packet* pkt=(packet*)lParam;
// 	//pcap_dumper_t* dumpfile=(pcap_dumper_t*)wParam;
// 	ShowPacketOnList(pkt);
// 	//myPcap.SavePacket(pkt,dumpfile);
// 	
// 	return 0;
// }

UINT CapThread(LPVOID lpParameter)
{	
	pcap_t *adhandle;
	pcap_if_t* devnow=(pcap_if_t*)lpParameter;
	char errbuf[PCAP_ERRBUF_SIZE+1];
	int res;
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	int num=0;
	CString errstring;
	u_int netmask;
	struct bpf_program fcode;

	if ( (adhandle= pcap_open(devnow->name,          // 设备名
		65536,            // 65536保证能捕获到不同数据链路层上的每个数据包的全部内容
		PCAP_OPENFLAG_PROMISCUOUS,    // 混杂模式
		1000,             // 读取超时时间
		NULL,             // 远程机器验证
		errbuf            // 错误缓冲池
		) ) == NULL)
	{
		errstring.Format(_T("Unable to open the adapter. %s is not supported by WinPcap"),CString(devnow->name));
		AfxMessageBox(errstring);
		pcap_freealldevs(devnow);
		//GetDlgItem(IDC_BUTTON1);
		return -1;
	}

	if (devnow->addresses != NULL)
		/* 获取接口第一个地址的掩码 */
		netmask=((struct sockaddr_in *)(devnow->addresses->netmask))->sin_addr.S_un.S_addr;

	else
		/* 如果这个接口没有地址，那么我们假设这个接口在C类网络中 */
		netmask=0xffffff; 
	/*char* packet_filter=CFilterDlg::UnicodeToANSI(filterstr.GetBuffer());*/
	if (pcap_compile(adhandle, &fcode, CStringA(filterstr.GetBuffer()), 1, netmask) <0 )
	{
		errstring=CString("Unable to compile the packet filter. Check the syntax.");
		AfxMessageBox(errstring);
		/* 释放设备列表 */
		pcap_freealldevs(devnow);
		return -1;
	}

	if (pcap_setfilter(adhandle, &fcode) < 0)
	{
		errstring=CString("Unable to set the filter.Please ensure the expression is correct");
		AfxMessageBox(errstring);
		pcap_freealldevs(devnow);
		return -1;
	}

	pcap_dumper_t* dumpfile;
	dumpfile=pcap_dump_open(adhandle,CStringA(CapFilePath.GetBuffer()));
	if(NULL==dumpfile)
	{
		AfxMessageBox(_T("Can't open the dump file!"));
		return -1;
	}
	while((res = pcap_next_ex( adhandle, &header, &pkt_data)) >= 0)
	{
		if(res == 0)
			/* 超时时间到 */
			continue;
		//_itoa(packetNum,list.num,10);
		//sprintf(list.time,timestr);
		
		//PostMessage(hmainDialog,WM_PACKET_IN,NULL,(LPARAM)pkt);
		/*SendMessageTimeout(hmainDialog,WM_UPDATE_LIST,(WPARAM)&list,0,SMTO_BLOCK,1000,&res);*/
		++num;
		time_t local_tv_sec;
		struct tm *ltime;
		char timestr[16];

		/* 将时间戳转换成可识别的格式 */
		local_tv_sec = header->ts.tv_sec;
		ltime=localtime(&local_tv_sec);
		strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);
		char temp[50];
		_itoa(num,temp,10);
		/*处理以太网首部*/
		ethernet_header *ethheader=(ethernet_header*)pkt_data;
		char protocaltype[10];
		CSnifferDlg::GetEthernetType(ethheader,protocaltype);

		TCHAR srcAddr[18];
		TCHAR desAddr[18];
		/*处理IPv4协议的类型*/
		if(CString(protocaltype)==CString("IPv4"))
		{
			/* 处理IP首部*/
			ip_header *ipheader= (ip_header *)(pkt_data+14); 
			swprintf_s(srcAddr,16,_T("%d.%d.%d.%d"),ipheader->saddr.byte1,ipheader->saddr.byte2,ipheader->saddr.byte3,ipheader->saddr.byte4);
			swprintf_s(desAddr,16,_T("%d.%d.%d.%d"),ipheader->daddr.byte1,ipheader->daddr.byte2,ipheader->daddr.byte3,ipheader->daddr.byte4);
			CSnifferDlg::GetIPv4Type(ipheader,protocaltype);
		}
		if(CString(protocaltype)==CString("ARP"))
		{	
			u_char* tmpSrc=ethheader->srcmac;
			u_char* tmpDst=ethheader->dstmac;
			swprintf_s(srcAddr,18,_T("%02X:%02X:%02X:%02X:%02X:%02X"),tmpSrc[0],tmpSrc[1],tmpSrc[2],tmpSrc[3],tmpSrc[4],tmpSrc[5]);
			swprintf_s(desAddr,18,_T("%02X:%02X:%02X:%02X:%02X:%02X"),tmpDst[0],tmpDst[1],tmpDst[2],tmpDst[3],tmpDst[4],tmpDst[5]);
		}
		/*确认为TCP包过后进一步判断协议类型*/
// 		if(CString(protocaltype)==CString("TCP"))
// 		{
// 			if(CSnifferDlg::IsHttp(header,pkt_data))
// 				strcpy_s(protocaltype,10,"HTTP");
// 		}
		/*处理包长度*/
		char lenstr[10];
		_itoa(header->len,lenstr,10);
		CSnifferDlg* 	mDlg=((CSnifferDlg*)(AfxGetApp()->GetMainWnd()));
		int i=mDlg->m_List.InsertItem(mDlg->m_List.GetItemCount(),CString(temp));
		//m_List.SetItemText(i,0,CString(list->num));

		mDlg->m_List.SetTextBkColor(0xFFE070);
		mDlg->m_List.SetItemText(i,0,CString(temp));
		mDlg->m_List.SetItemText(i,1,CString(timestr));
		mDlg->m_List.SetItemText(i,2,CString(srcAddr));
		mDlg->m_List.SetItemText(i,3,CString(desAddr));
		mDlg->m_List.SetItemText(i,4,CString(protocaltype));
		mDlg->m_List.SetItemText(i,5,CString(lenstr));
		EnterCriticalSection(&CapThreadCS);
// 		if((CString)protocaltype==CString("ARP"))
// 			++arpnum;
// 		if((CString)protocaltype==CString("TCP"))
// 		{
// 			tcpnum++;
// 			CFile mFile;
// 			mFile.Open(_T("num.dat"),CFile::modeWrite|CFile::modeCreate);
// 			CArchive ar(&mFile,CArchive::store);
// 			ar<<tcpnum;
// 		}
// 		if((CString)protocaltype==CString("UDP"))
// 			++udpnum;
// 		if((CString)protocaltype==CString("ICMP"))
// 			++icmpnum;
// 		if((CString)protocaltype==CString("IGMP"))
// 			++igmpnum;
		LeaveCriticalSection(&CapThreadCS);
		CMyPcap::SavePacket(header,pkt_data,dumpfile);
	}

	if(res == -1){
		CString errstr;
		errstr.Format(_T("Error reading the packets: %s\n"), CString(pcap_geterr(adhandle)));
		AfxMessageBox(errstr);
		return -1;
	}

	return 0;
}


void CSnifferDlg::OnBnClickedButton2()
{
	// TODO: Add your control notification handler code here
	if(TerminateThread(hCapThread->m_hThread,2)==FALSE)
	{
		AfxMessageBox(_T("Stop CapThread Fail,perhaps it has stopped yet!"));
	}
	GetDlgItem(IDC_BUTTON1)->EnableWindow(TRUE);
	GetDlgItem(IDC_BUTTON2)->EnableWindow(FALSE);
	GetDlgItem(IDC_BUTTON5)->EnableWindow(TRUE);
	GetDlgItem(IDC_BUTTON6)->EnableWindow(FALSE);
// 	GetMenu()->GetSubMenu(1)->EnableMenuItem(ID_CAPTURE_START, MF_BYCOMMAND|MF_ENABLED);
// 	GetMenu()->GetSubMenu(1)->EnableMenuItem(ID_CAPTURE_STOP, MF_BYCOMMAND|MF_DISABLED|MF_GRAYED);
	capStatus=FALSE;
}

void CSnifferDlg::OnClose()
{
	// TODO: Add your message handler code here and/or call default
	if(capStatus)
	{
		AfxMessageBox(_T("Please stop capture first!"));
		return;
	}
	DeleteCriticalSection(&CapThreadCS);
	pcap_freealldevs(alldevs);
	CDialog::OnClose();
}

// void CSnifferDlg::ShowPacketOnList(packet* p)
// {
// 	++num;
// 	time_t local_tv_sec;
// 	struct tm *ltime;
// 	char timestr[16];
// 	struct pcap_pkthdr* header=p->header;
// 	const u_char* pkt_data=p->pkt_data;
// 
// 	/* 将时间戳转换成可识别的格式 */
// 	local_tv_sec = header->ts.tv_sec;
// 	ltime=localtime(&local_tv_sec);
// 	strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);
// 	char temp[50];
// 	_itoa(num,temp,10);
// 	/*处理以太网首部*/
// 	ethernet_header *ethheader=(ethernet_header*)pkt_data;
// 	char protocaltype[10];
// 	GetEthernetType(ethheader,protocaltype);
// 	/* 处理IP首部*/
// 	ip_header *ipheader= (ip_header *)(pkt_data+14); 
// 	char ipsrcAddr[16];
// 	char ipdesAddr[16];
// 	sprintf_s(ipsrcAddr,16,("%d.%d.%d.%d"),ipheader->saddr.byte1,ipheader->saddr.byte2,ipheader->saddr.byte3,ipheader->saddr.byte4);
// 	sprintf_s(ipdesAddr,16,("%d.%d.%d.%d"),ipheader->daddr.byte1,ipheader->daddr.byte2,ipheader->daddr.byte3,ipheader->daddr.byte4);
// 	/*处理IPv4协议的类型*/
// 	if(CString(protocaltype)==CString("IPv4"))
// 	{
// 		GetIPv4Type(ipheader,protocaltype);
// 	}
// // 	if(CString(protocaltype)==CString("UNKNOW"))
// // 	{
// // 		_itoa(int(ethheader->eth_type),protocaltype,16);
// // 	}
// // 	TCHAR ip_srcAddr[16];
// // 	TCHAR ip_dstAddr[16];
// // 	CString ip_strProtocol = NULL;
// // 	GetIPAddress(ip_srcAddr,&ip_hdr->srcaddr);
// // 	GetIPAddress(ip_dstAddr,&ip_hdr->dstaddr);
// // 	GetIPType(ip_strProtocol,ip_hdr->protocol,true);
// 	/*处理包长度*/
// 	char lenstr[10];
// 	_itoa(header->len,lenstr,10);
// 	
// 	int i=m_List.InsertItem(m_List.GetItemCount(),CString(temp));
// 	//m_List.SetItemText(i,0,CString(list->num));
// 	m_List.SetItemText(i,0,CString(temp));
// 	m_List.SetItemText(i,1,CString(timestr));
// 	m_List.SetItemText(i,2,CString(ipsrcAddr));
// 	m_List.SetItemText(i,3,CString(ipdesAddr));
// 	m_List.SetItemText(i,4,CString(protocaltype));
// 	m_List.SetItemText(i,5,CString(lenstr));
// }

void CSnifferDlg::GetEthernetType(ethernet_header * e,char *typestr)
{
	u_short etype=ntohs(e->eth_type);
	switch(etype)
	{
	case XNS_IDP :
		strcpy_s(typestr,10,("XNS IDP"));
		break;
	case DLOG :
		strcpy_s(typestr,10,("DLOG"));
		break;
	case IP:
		strcpy_s(typestr,10,("IPv4"));
		break;
	case X75:
		strcpy_s(typestr,10,("X.75"));
		break;
	case NBS:
		strcpy_s(typestr,10,("NBS"));
		break;
	case ECMA :
		strcpy_s(typestr,10,("ECMA"));
		break;
	case Chaosnet :
		strcpy_s(typestr,10,("Chaosnet"));
		break;
	case X25L3 :
		strcpy_s(typestr,10,("X25 L3"));
		break;
	case ARP :
		strcpy_s(typestr,10,("ARP"));
		break;
	case FARP:
		strcpy_s(typestr,10,("FARP"));
		break;
	case RFR:
		strcpy_s(typestr,10,("RFR"));
		break;
	case RARP :
		strcpy_s(typestr,10,("RARP"));
		break;
	case NNIPX:
		strcpy_s(typestr,10,("NNIPX"));
		break;
	case EtherTalk :
		strcpy_s(typestr,10,("EtherTalk"));
		break;
	case ISSE :
		strcpy_s(typestr,10,("ISSE"));
		break;
	case AARP:
		strcpy_s(typestr,10,("AAPR"));
		break;
	case EAPS:
		strcpy_s(typestr,10,("EAPS"));
		break;
	case IPX :
		strcpy_s(typestr,10,("IPX"));
		break;
	case SNMP:
		strcpy_s(typestr,10,("SNMP"));
		break;
	case IPv6 :
		strcpy_s(typestr,10,("IPv6"));
		break;
	case OAM:
		strcpy_s(typestr,10,("OAM"));
		break;
	case PPP :
		strcpy_s(typestr,10,("PPP"));
		break;
	case GSMP :
		strcpy_s(typestr,10,("GSMP"));
		break;
	case MPLSu :
		strcpy_s(typestr,10,("MPLS"));
		break;
	case MPLSm :
		strcpy_s(typestr,10,("MPLS"));
		break;
	case PPPoEds :
		strcpy_s(typestr,10,("PPPoE"));
		break;
	case PPPoEss :
		strcpy_s(typestr,10,("PPPoE"));
		break;
	case LWAPP :
		strcpy_s(typestr,10,("LWAPP"));
		break;
	case LLDP :
		strcpy_s(typestr,10,("LLDP"));
		break;
	case EAP:
		strcpy_s(typestr,10,("EAP"));
		break;
	case LOOPBACK :
		strcpy_s(typestr,10,("LOOPBACK"));
		break;
	case VLAN :
		strcpy_s(typestr,10,("VLAN"));
		break;
	default:
		strcpy_s(typestr,10,("UNKNOW"));
		break;
	}
}

void CSnifferDlg::GetIPv4Type(ip_header* ih, char* pt)
{
	u_short iptype=ih->proto;
	switch (iptype)
	{
	case ICMP:
		strcpy_s(pt,10,"ICMP");
		break;
	case IGMP:
		strcpy_s(pt,10,"IGMP");
		break;
	case TCP:
		strcpy_s(pt,10,"TCP");
		break;
	case UDP:
		strcpy_s(pt,10,"UDP");
		break;
	case OSPF:
		strcpy_s(pt,10,"OSPF");
		break;
	default:
		strcpy_s(pt,10,"UNKNOW IP");
	}
}



void CSnifferDlg::OnNMClickList2(NMHDR *pNMHDR, LRESULT *pResult)
{
	//LPNMITEMACTIVATE pNMItemActivate = reinterpret_cast<NMITEMACTIVATE>(pNMHDR);
	// TODO: Add your control notification handler code here
	NM_LISTVIEW* pNMListView = (NM_LISTVIEW*)pNMHDR;
// 	struct pcap_pkthdr *header;
// 	const u_char *pkt_data;
	if(pNMListView->iItem != -1)
	{
		int ItemClick = pNMListView->iItem;
		AfxBeginThread(ReadDumpThread,(LPVOID)ItemClick);
	}
	*pResult = 0;
}

UINT ReadDumpThread(LPVOID lpParameter)
{/*这个线程用于从临时文件中读取选择的包并将其分析生成分析树*/
	int packetFind=(int)lpParameter;
	pcap_t *adhandle;
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	char errbuff[PCAP_ERRBUF_SIZE+1];
	//char* show=new char[];
	CString data;
	//CString tmp;
	CSnifferDlg* mDlg=((CSnifferDlg*)(AfxGetApp()->GetMainWnd()));
	if(NULL==(adhandle=pcap_open_offline(CStringA(CapFilePath.GetBuffer()),errbuff)))
	{
	CString errstr;
	errstr.Format(_T("Open dump file error,error code:s%"),errbuff);
	AfxMessageBox(errstr);
	return -1;
	}
	for(int i=0;i<=packetFind;i++)
	{
		pcap_next_ex(adhandle,&header,&pkt_data);
	}
	data=CSnifferDlg::PackToEdit(header,pkt_data);
	/*处理以太网首部*/
	ethernet_header *ethheader=(ethernet_header*)pkt_data;
	char type[10];//以太网包类型
	CSnifferDlg::GetEthernetType(ethheader,type);
	// 获取MAC地址
	TCHAR eth_src[18];
	TCHAR eth_dst[18];
	u_char* tmpSrc;
	u_char* tmpDst;
	tmpSrc=ethheader->srcmac;
	tmpDst=ethheader->dstmac;
	swprintf_s(eth_src,18,_T("%02X:%02X:%02X:%02X:%02X:%02X"),tmpSrc[0],tmpSrc[1],tmpSrc[2],tmpSrc[3],tmpSrc[4],tmpSrc[5]);
	swprintf_s(eth_dst,18,_T("%02X:%02X:%02X:%02X:%02X:%02X"),tmpDst[0],tmpDst[1],tmpDst[2],tmpDst[3],tmpDst[4],tmpDst[5]);
	mDlg->SetDlgItemText(IDC_EDIT1,data);
	mDlg->m_InfoTree.DeleteAllItems();
	char Frame[1024];
	CString str;
	//Frame
	sprintf_s(Frame,1024,"Frame %d: %u bytes on wire (%u bits)",(packetFind+1),header->len,(header->len)*8);
	HTREEITEM HFrame=mDlg->m_InfoTree.InsertItem(CString(Frame));
	//Ethernet
	str.Format(_T("Ethernet,Src:  %s,Dst:  %s"),eth_src,eth_dst);
	HTREEITEM HEthernet=mDlg->m_InfoTree.InsertItem(str);

	//Ethernet Source
	str.Format(_T("Source:  %s"),eth_src);
	mDlg->m_InfoTree.InsertItem(str,HEthernet,TVI_LAST);

	//Ethernet Destination
	str.Format(_T("Destination:  %s"),eth_dst);
	mDlg->m_InfoTree.InsertItem(str,HEthernet,TVI_LAST);
	//Ethernet Type
	str=CString("Type:  ")+CString(type);
	mDlg->m_InfoTree.InsertItem(str,HEthernet,TVI_LAST);
	if((CString)type==CString("IPv4"))
	{
		ip_header* ipheader=(ip_header*)(pkt_data+14);
		u_short ipLen=ipheader->ihl*4;
		CSnifferDlg::ShowIPInfo(pkt_data,mDlg);
		CSnifferDlg::GetIPv4Type(ipheader,type);
		if((CString)type==CString("UDP"))
		{
			udp_header* udpheader=(udp_header*)(pkt_data+14+ipLen);
			CSnifferDlg::ShowUDPInfo(udpheader,mDlg);
		}
		if((CString)type==CString("ICMP"))
		{
			icmp_header* icmpheader=(icmp_header*)(pkt_data+14+ipLen);
			CSnifferDlg::ShowICMPInfo(icmpheader,mDlg);
		}
		if((CString)type==CString("IGMP"))
		{
			igmp_header* igmpheader=(igmp_header*)(pkt_data+14+ipLen);
			CSnifferDlg::ShowIGMPInfo(igmpheader,mDlg);
		}
		if((CString)type==CString("TCP"))
		{
			tcp_header* tcpheader=(tcp_header*)(pkt_data+14+ipLen);
			u_short tcpdataLen=header->len-14-ipLen-tcpheader->offset*4;
			CSnifferDlg::ShowTCPInfo(tcpheader,mDlg,tcpdataLen);
		}
	}
	if((CString)type==CString("ARP"))
	{
		arp_header* arpheader=(arp_header*)(pkt_data+14);
		CSnifferDlg::ShowArpInfo(arpheader,mDlg);
	}
	return 0; 
}

BOOL CSnifferDlg::IsHttp(struct pcap_pkthdr *header,const u_char* pkt_data)
{
// 	ip_header* ipheader=(ip_header*)(p+14);
// 	u_short ipLen=ipheader->ihl*4;
// 	tcp_header* tcpheader=(tcp_header*)(p+14+ipLen);
// 	u_short tcpLen=tcpheader->offset*4;
// 	
// 	u_char* httppac=(u_char*)p+14+ipLen+tcpLen;
// 	u_short httpLen=ntohs(ipheader->tlen)-ipLen-tcpLen;
// 	char tmp[10];
// 	CString res;
// 	for(int i=0;i<httpLen;i++)
// 	{
// 		sprintf_s(tmp,10,"%c",httppac[i]);
// 		res+=(CString)tmp;
// 		if(i>2&&13==httppac[i-1]&&10==httppac[i])
// 			break;
// 	}
// 	int httppos=res.Find(_T("HTTP"),0);
// 	if(httppos!=-1&&httppos!=65535)
// 		return TRUE;
// 	else
// 		return FALSE;
	ip_header* ipheader=(ip_header*)(pkt_data+14);
	u_short ipLen=ipheader->ihl*4;
	tcp_header* tcpheader=(tcp_header*)(pkt_data+14+ipLen);
	u_short tcpLen=tcpheader->offset*4;
	 	
	u_char* httppac=(u_char*)pkt_data+14+ipLen+tcpLen;
	u_short httpLen=ntohs(ipheader->tlen)-ipLen-tcpLen;
	char s[64];
	CString data;
	char ipDataOut[65535]={0};
	int end=0;
	if(httpLen>0)
	{
		for(int i=0;i<=httpLen;i++)
		{
			if(isgraph(httppac[i]))
				ipDataOut[end]=httppac[i];
			else if(isgraph(httppac[i])==' ')
				ipDataOut[end]=httppac[i];
			else ipDataOut[end]='.';
			++end;
			if(i>2&&13==httppac[i-1]&&10==httppac[i])
				break;
		}
		ipDataOut[end]='\0';
	}
	
	int httppos=(CString(ipDataOut)).Find(_T("HTTP"));
	if(httppos!=-1&&httppos!=65536)
		return TRUE;
	else
		return FALSE;
}

CString CSnifferDlg::PackToEdit(struct pcap_pkthdr* header, const u_char* pkt_data)
{
	CString data;
	char s[64];
	int ipDataLength=header->len;
	char ipDataOut[65535]={0};
	int end=0;
	if(ipDataLength>0)
	{
		for(int i=0;i<=ipDataLength;i++)
		{
			//printf("%02x",pkt_data[i]);
			//tmp.Format(_T(" %02x"),pkt_data[i]);
			sprintf_s(s,64," %02X",pkt_data[i]);
			data+=(CString)s;
			if(isgraph(pkt_data[i]))
				ipDataOut[end]=pkt_data[i];
			else if(isgraph(pkt_data[i])==' ')
				ipDataOut[end]=pkt_data[i];
			else ipDataOut[end]='.';
			end=end+1;

			if(i%16==15)
			{
				ipDataOut[end]='\0';
				/*printf("  %s",ipDataOut);*/
				//sprintf(show,"  %s")
				//tmp.Format(_T("  %s"),ipDataOut);
				sprintf_s(s,64," %s",ipDataOut);
				data+=(CString)s;
				end=0;
				//printf("\n");
				data+=CString("\r\n");
			}
		}

		if(end>0)
		{
			for(int k=end*3;k<48;k++)
			{
				//printf("");
				data+=CString(" ");
			}
			ipDataOut[end]=0;
			// 			printf("  %s",ipDataOut);
			// 			printf("\n");
			//tmp.Format(("  %s"),ipDataOut);
			sprintf_s(s,64," %s",ipDataOut);
			data+=(CString) s;
			data+=CString("\r\n");
		}
	}
	return data;
}

void CSnifferDlg::DecToBinary(int n, char* ch)
{
	for(int i=0;i<8;i++)
	{
		if((n&0x80)==0x80)
			ch[i]='1';
		else
			ch[i]='0';
		n<<1;
	}
}

void CSnifferDlg::ShowIPInfo(const u_char* pkt_data,CSnifferDlg* mDlg)
{
	CString str;
	char iptype[10];
	ip_header *ipheader= (ip_header *)(pkt_data+14); 
	TCHAR ipsrcAddr[16];
	TCHAR ipdesAddr[16];
	swprintf_s(ipsrcAddr,16,_T("%d.%d.%d.%d"),ipheader->saddr.byte1,ipheader->saddr.byte2,ipheader->saddr.byte3,ipheader->saddr.byte4);
	swprintf_s(ipdesAddr,16,_T("%d.%d.%d.%d"),ipheader->daddr.byte1,ipheader->daddr.byte2,ipheader->daddr.byte3,ipheader->daddr.byte4);
	CSnifferDlg::GetIPv4Type(ipheader,iptype);
	//IP
	str.Format(_T("Internet Protocol Version 4,Src:  %s,Dst:  %s"),ipsrcAddr,ipdesAddr);
	HTREEITEM HIPv4=mDlg->m_InfoTree.InsertItem(str);
	//Version
	str=CString("Version:  4");
	mDlg->m_InfoTree.InsertItem(str,HIPv4,TVI_LAST);
	//Header Length
	u_short iphLen=ipheader->ihl*4;
	str.Format(_T("Header length:  %u bytes"),iphLen);
	mDlg->m_InfoTree.InsertItem(str,HIPv4,TVI_LAST);
	//Services
	int dscp=((ipheader->tos)&(0xEC))>>2;
	int ecn=(ipheader->tos)&(0x03);
	str.Format(_T("Differentiated Services Field: 0x%02x (DSCP 0x%02x; ECN: 0x%02x)"),ipheader->tos,dscp,ecn);
	HTREEITEM HSer=mDlg->m_InfoTree.InsertItem(str,HIPv4,TVI_LAST);
	//Ser Dscp Ecn
	char tosb[8];
	CSnifferDlg::DecToBinary(int(ipheader->tos),tosb);
	str.Format(_T("Differentiated Services Codepoint: %c%c%c%c %c%c.."),tosb[0],tosb[1],tosb[2],tosb[3],tosb[4],tosb[5]);
	mDlg->m_InfoTree.InsertItem(str,HSer,TVI_LAST);
	str.Format(_T("Explicit Congestion Notification:  .... ..%c%c"),tosb[6],tosb[7]);
	mDlg->m_InfoTree.InsertItem(str,HSer,TVI_LAST);
	//Total Length
	str.Format(_T("Total Length: %d"),ntohs(ipheader->tlen));
	mDlg->m_InfoTree.InsertItem(str,HIPv4,TVI_LAST);
	//Identification
	str.Format(_T("Identification: %04x (%d)"),ntohs(ipheader->identification),ntohs(ipheader->identification));
	mDlg->m_InfoTree.InsertItem(str,HIPv4,TVI_LAST);
	//Flags
	str.Format(_T("Flags: 0x%02x"),ipheader->flags);
	HTREEITEM HFlag=mDlg->m_InfoTree.InsertItem(str,HIPv4,TVI_LAST);
	//Flags Detail
	char flagsb[8];
	CSnifferDlg::DecToBinary((int)(ipheader->flags),flagsb);
	str.Format(_T("%c.. = Reserved bit: %s"),flagsb[5],(flagsb[5]>'0')?_T("Set"):_T("Not Set"));
	mDlg->m_InfoTree.InsertItem(str,HFlag,TVI_LAST);
	str.Format(_T(".%c. = Don't fragment: %s"),flagsb[6],(flagsb[6]>'0')?_T("Set"):_T("Not Set"));
	mDlg->m_InfoTree.InsertItem(str,HFlag,TVI_LAST);
	str.Format(_T("..%c = More fragments: %s"),flagsb[7],(flagsb[6]>'0')?_T("Set"):_T("Not Set"));
	mDlg->m_InfoTree.InsertItem(str,HFlag,TVI_LAST);
	//Flag Offset
	str.Format(_T("Fragment offset: %d"),ipheader->fo);
	mDlg->m_InfoTree.InsertItem(str,HIPv4,TVI_LAST);
	//Time to Live
	str.Format(_T("Time to live: %d"),ipheader->ttl);
	mDlg->m_InfoTree.InsertItem(str,HIPv4,TVI_LAST);
	//Protocol
	char protocol[10];
	CSnifferDlg::GetIPv4Type(ipheader,protocol);
	str=CString("Protocol: ")+CString(protocol);
	mDlg->m_InfoTree.InsertItem(str,HIPv4,TVI_LAST);
	//Check Sum
	str.Format(_T("Header checksum: 0x%04x"),ntohs(ipheader->crc));
	mDlg->m_InfoTree.InsertItem(str,HIPv4,TVI_LAST);
	//Source
	str.Format(_T("Source: %s"),ipsrcAddr);
	mDlg->m_InfoTree.InsertItem(str,HIPv4,TVI_LAST);
	//Destination
	str.Format(_T("Destination: %s"),ipdesAddr);
}

void CSnifferDlg::ShowArpInfo(arp_header* arpheader, CSnifferDlg* mDlg)
{
	CString str;
	str.Format(_T("Address Resolution Protocol (%s)"),(1==ntohs(arpheader->opcode))?_T("request"):_T("reply"));
	HTREEITEM HArp=mDlg->m_InfoTree.InsertItem(str);
	//Hardware Type
	switch(ntohs(arpheader->hrd))
	{
	case 1:
		str=CString("Hardware Type: Ethernet (1)");
		break;
	case 6:
		str=CString("Hardware Type: Token Ring (6)");
		break;
	default:
		str.Format(_T("Hardware Type: Unknow (%d)"),ntohs(arpheader->eth_type));
	}
	mDlg->m_InfoTree.InsertItem(str,HArp,TVI_LAST);
	//Prptocol Type
	if(2048==ntohs(arpheader->eth_type))
		str=CString("Protocol type: IP (0x0800)");
	else
		str=CString("Protocol type: Unknow");
	mDlg->m_InfoTree.InsertItem(str,HArp,TVI_LAST);
	//Hardware Size
	str.Format(_T("Hardware size: %d"),arpheader->maclen);
	mDlg->m_InfoTree.InsertItem(str,HArp,TVI_LAST);
	//Protocol Size
	str.Format(_T("Protocol size: %d"),arpheader->iplen);
	mDlg->m_InfoTree.InsertItem(str,HArp,TVI_LAST);
	//Opcode
	str.Format(_T("Opcode: %s"),(1==ntohs(arpheader->opcode))?_T("request (1)"):_T("reply (2)"));
	mDlg->m_InfoTree.InsertItem(str,HArp,TVI_LAST);
	//Sender Mac
	u_char* tmpSrc=arpheader->smac;
	str.Format(_T("Sender MAC address: %02X:%02X:%02X:%02X:%02X:%02X"),tmpSrc[0],tmpSrc[1],tmpSrc[2],tmpSrc[3],tmpSrc[4],tmpSrc[5]);
	mDlg->m_InfoTree.InsertItem(str,HArp,TVI_LAST);
	//Sender IP
	str.Format(_T("Sender IP address: %d.%d.%d.%d"),arpheader->saddr.byte1,arpheader->saddr.byte2,arpheader->saddr.byte3,arpheader->saddr.byte4);
	mDlg->m_InfoTree.InsertItem(str,HArp,TVI_LAST);
	//Target Mac
	u_char* tmpDst=arpheader->dmac;
	str.Format(_T("Target MAC address: %02X:%02X:%02X:%02X:%02X:%02X"),tmpDst[0],tmpDst[1],tmpDst[2],tmpDst[3],tmpDst[4],tmpDst[5]);
	mDlg->m_InfoTree.InsertItem(str,HArp,TVI_LAST);
	//Target IP
	str.Format(_T("Target IP address: %d.%d.%d.%d"),arpheader->daddr.byte1,arpheader->daddr.byte2,arpheader->daddr.byte3,arpheader->daddr.byte4);
	mDlg->m_InfoTree.InsertItem(str,HArp,TVI_LAST);
}

void CSnifferDlg::ShowUDPInfo(udp_header* udpheader, CSnifferDlg* mDlg)
{
	CString str;
	str.Format(_T("User Datagram Protocol, Src Port: %d, Dst Port: %d"),ntohs(udpheader->sport),ntohs(udpheader->dport));
	HTREEITEM HUDP=mDlg->m_InfoTree.InsertItem(str);
	//Source Port
	str.Format(_T("Source port: %d"),ntohs(udpheader->sport));
	mDlg->m_InfoTree.InsertItem(str,HUDP,TVI_LAST);
	//Destination Port
	str.Format(_T("Destination port: %d"),ntohs(udpheader->dport));
	mDlg->m_InfoTree.InsertItem(str,HUDP,TVI_LAST);
	//Length
	str.Format(_T("Length: %d"),ntohs(udpheader->len));
	mDlg->m_InfoTree.InsertItem(str,HUDP,TVI_LAST);
	//CheckSum
	str.Format(_T("CheckSum: 0x%04x"),ntohs(udpheader->crc));
	mDlg->m_InfoTree.InsertItem(str,HUDP,TVI_LAST);
	u_char* data=(u_char*)(udpheader+udpheader->len);
	//Data
	u_short datasize=ntohs(udpheader->len)-8;
	str.Format(_T("Data (%d bytes)"),datasize);
	mDlg->m_InfoTree.InsertItem(str,HUDP,TVI_LAST);
}

void CSnifferDlg::ShowICMPInfo(icmp_header* icmpheader, CSnifferDlg* mDlg)
{
	CString str;
	str=CString("Internet Control Message Protocol");
	HTREEITEM HICMP=mDlg->m_InfoTree.InsertItem(str);
	//Type
	TCHAR Type[64];
	HTREEITEM HIC_Type;
	switch (icmpheader->type)
	{
	case ICMP4_ECHO_REPLY:
		wcscpy_s(Type,64,_T("Echo (ping) reply"));
		str.Format(_T("Type: %d (%s)"),icmpheader->type,Type);
		HIC_Type=mDlg->m_InfoTree.InsertItem(str,HICMP,TVI_LAST);
		str.Format(_T("Identifier (Big Endian): %d"),ntohs(icmpheader->id));
		mDlg->m_InfoTree.InsertItem(str,HICMP,TVI_LAST);
		str.Format(_T("Identifier (Little Endian): %d"),icmpheader->id);
		mDlg->m_InfoTree.InsertItem(str,HICMP,TVI_LAST);
		str.Format(_T("Sequence number (Big Endian): %d"),ntohs(icmpheader->seq));
		mDlg->m_InfoTree.InsertItem(str,HICMP,TVI_LAST);
		str.Format(_T("Sequence number (Little Endian): %d"),icmpheader->seq);
		mDlg->m_InfoTree.InsertItem(str,HICMP,TVI_LAST);
		break;
	case ICMP4_ECHO_REQUEST:
		wcscpy_s(Type,64,_T("Echo (ping) request"));
		str.Format(_T("Type: %d (%s)"),icmpheader->type,Type);
		HIC_Type=mDlg->m_InfoTree.InsertItem(str,HICMP,TVI_LAST);
		str.Format(_T("Identifier (Big Endian): %d"),ntohs(icmpheader->id));
		mDlg->m_InfoTree.InsertItem(str,HICMP,TVI_LAST);
		str.Format(_T("Identifier (Little Endian): %d"),icmpheader->id);
		mDlg->m_InfoTree.InsertItem(str,HICMP,TVI_LAST);
		str.Format(_T("Sequence number (Big Endian): %d"),ntohs(icmpheader->seq));
		mDlg->m_InfoTree.InsertItem(str,HICMP,TVI_LAST);
		str.Format(_T("Sequence number (Little Endian): %d"),icmpheader->seq);
		mDlg->m_InfoTree.InsertItem(str,HICMP,TVI_LAST);
		break;
	case ICMP4_MASK_REPLY:
		wcscpy_s(Type,64,_T("Mask reply"));
		str.Format(_T("Type: %d (%s)"),icmpheader->type,Type);
		HIC_Type=mDlg->m_InfoTree.InsertItem(str,HICMP,TVI_LAST);
		break;
	case ICMP4_MASK_REQUEST:
		wcscpy_s(Type,64,_T("Mask request"));
		str.Format(_T("Type: %d (%s)"),icmpheader->type,Type);
		HIC_Type=mDlg->m_InfoTree.InsertItem(str,HICMP,TVI_LAST);
		break;
	case ICMP4_ROUTER_SOLICIT:
		wcscpy_s(Type,64,_T("Router solicit"));
		str.Format(_T("Type: %d (%s)"),icmpheader->type,Type);
		HIC_Type=mDlg->m_InfoTree.InsertItem(str,HICMP,TVI_LAST);
		break;
	case ICMP4_DST_UNREACH:
		wcscpy_s(Type,64,_T("Dest unreach"));
		str.Format(_T("Type: %d (%s)"),icmpheader->type,Type);
		HIC_Type=mDlg->m_InfoTree.InsertItem(str,HICMP,TVI_LAST);
		break;
	case ICMP4_SOURCE_QUENCH:
		wcscpy_s(Type,64,_T("Source quench"));
		str.Format(_T("Type: %d (%s)"),icmpheader->type,Type);
		HIC_Type=mDlg->m_InfoTree.InsertItem(str,HICMP,TVI_LAST);
		break;
	case ICMP4_REDIRECT:
		wcscpy_s(Type,64,_T("Redirect"));
		str.Format(_T("Type: %d (%s)"),icmpheader->type,Type);
		HIC_Type=mDlg->m_InfoTree.InsertItem(str,HICMP,TVI_LAST);
		break;
	case ICMP4_ROUTER_ADVERT:
		wcscpy_s(Type,64,_T("Router Advert"));
		str.Format(_T("Type: %d (%s)"),icmpheader->type,Type);
		HIC_Type=mDlg->m_InfoTree.InsertItem(str,HICMP,TVI_LAST);
		break;
	case ICMP4_TIME_EXCEEDED:
		wcscpy_s(Type,64,_T("Time exceeded"));
		str.Format(_T("Type: %d (%s)"),icmpheader->type,Type);
		HIC_Type=mDlg->m_InfoTree.InsertItem(str,HICMP,TVI_LAST);
		break;
	case ICMP4_PARAM_PROB:
		wcscpy_s(Type,64,_T("Param prob"));
		str.Format(_T("Type: %d (%s)"),icmpheader->type,Type);
		HIC_Type=mDlg->m_InfoTree.InsertItem(str,HICMP,TVI_LAST);
		break;
	case ICMP4_TIMESTAMP_REQUEST:
		wcscpy_s(Type,64,_T("Timestamp request"));
		str.Format(_T("Type: %d (%s)"),icmpheader->type,Type);
		HIC_Type=mDlg->m_InfoTree.InsertItem(str,HICMP,TVI_LAST);
		break;
	case ICMP4_TIMESTAMP_REPLY:
		wcscpy_s(Type,64,_T("Timestamp reply"));
		str.Format(_T("Type: %d (%s)"),icmpheader->type,Type);
		HIC_Type=mDlg->m_InfoTree.InsertItem(str,HICMP,TVI_LAST);
		break;

	}
	//Code
	str.Format(_T("Code: %d"),icmpheader->code);
	HTREEITEM HIC_Code=mDlg->m_InfoTree.InsertItem(str,HICMP,HIC_Type);
	//CheckSum
	str.Format(_T("Checksum:0x%04x"),ntohs(icmpheader->chk_sum));
	mDlg->m_InfoTree.InsertItem(str,HICMP,HIC_Code);
}

void CSnifferDlg::ShowIGMPInfo(igmp_header* igmpheader, CSnifferDlg* mDlg)
{
	CString str;
	str=CString("Internet Group Management Protocol");
	HTREEITEM HIGMP=mDlg->m_InfoTree.InsertItem(str);
	//Type
	switch(igmpheader->type)
	{
	case 0x11:
		str.Format(_T("Type:Membership Query (0x%02x)"),igmpheader->type);
		break;
	case 0x16:
		str.Format(_T("Type:Membership Report (0x%02x)"),igmpheader->type);
		break;
	case 0x17:
		str.Format(_T("Type:Leave Group (0x%02x)"),igmpheader->type);
		break;
	}
	mDlg->m_InfoTree.InsertItem(str,HIGMP,TVI_LAST);
	//Max Response Time
	str.Format(_T("Max response time: %d sec (0x%02x)"),(igmpheader->mrtime)/10.0,igmpheader->mrtime);
	mDlg->m_InfoTree.InsertItem(str,HIGMP,TVI_LAST);
	//Checksum
	str.Format(_T("Header Checksum: 0x%04x"),igmpheader->chk_sum);
	mDlg->m_InfoTree.InsertItem(str,HIGMP,TVI_LAST);
	//Multicast add
	str.Format(_T("Multicast Address: %d.%d.%d.%d"),(igmpheader->mcadd&0xff000000)>>24,(igmpheader->mcadd&0x00ff0000)>>16,(igmpheader->mcadd&0x0000ff00)>>8,(igmpheader->mcadd&0x000000ff));
	mDlg->m_InfoTree.InsertItem(str,HIGMP,TVI_LAST);
}

void CSnifferDlg::ShowTCPInfo(tcp_header* tcpheader, CSnifferDlg* mDlg, u_short tcpdataLen)
{
	CString str;
	str.Format(_T("Transmission Control Protocol, Src Port: %d,Dst Port: %d"),ntohs(tcpheader->sport),ntohs(tcpheader->dport));
	HTREEITEM HTCP=mDlg->m_InfoTree.InsertItem(str);
	//Source Port
	str.Format(_T("Source port: %d"),ntohs(tcpheader->sport));
	mDlg->m_InfoTree.InsertItem(str,HTCP,TVI_LAST);
	//Des Port
	str.Format(_T("Destination port: %d"),ntohs(tcpheader->dport));
	mDlg->m_InfoTree.InsertItem(str,HTCP,TVI_LAST);
	//Seq num
	str.Format(_T("Sequence number: %u"),ntohl(tcpheader->seqno));
	mDlg->m_InfoTree.InsertItem(str,HTCP,TVI_LAST);
	//Ack num

	u_char* tcpdata=(u_char*)tcpheader;
	if(1==tcpheader->flag&0x10)
	{
		str.Format(_T("Acknowledgement number: %u"),ntohl(tcpheader->ackno));
	}
	else
	{
		str=CString("Acknowledgement number: Acknowledgement Flag not set");
	}
	mDlg->m_InfoTree.InsertItem(str,HTCP,TVI_LAST);
	//Header Length
	str.Format(_T("Header Length: %d bytes"),tcpheader->offset*4);
	mDlg->m_InfoTree.InsertItem(str,HTCP,TVI_LAST);
	//Flags
	str.Format(_T("Flags: 0x%02x"),tcpheader->flag);
	HTREEITEM HT_Flag=mDlg->m_InfoTree.InsertItem(str,HTCP,TVI_LAST);
	str.Format(_T("..%d..... = Urgent: %s"),(tcpheader->flag&0x20)>>5,(1==(tcpheader->flag&0x20)>>5)?_T("Set"):_T("Not Set"));
	mDlg->m_InfoTree.InsertItem(str,HT_Flag,TVI_LAST);
	str.Format(_T("...%d.... = Acknowledgement: %s"),(tcpheader->flag&0x10)>>4,(1==(tcpheader->flag&0x10)>>4)?_T("Set"):_T("Not Set"));
	mDlg->m_InfoTree.InsertItem(str,HT_Flag,TVI_LAST);
	str.Format(_T("....%d... = Push: %s"),(tcpheader->flag&0x08)>>3,(1==(tcpheader->flag&0x08)>>3)?_T("Set"):_T("Not Set"));
	mDlg->m_InfoTree.InsertItem(str,HT_Flag,TVI_LAST);
	str.Format(_T(".....%d.. = Reset: %s"),(tcpheader->flag&0x04)>>2,(1==(tcpheader->flag&0x04)>>2)?_T("Set"):_T("Not Set"));
	mDlg->m_InfoTree.InsertItem(str,HT_Flag,TVI_LAST);
	str.Format(_T("......%d. = Syn: %s"),(tcpheader->flag&0x02)>>1,(1==(tcpheader->flag&0x02)>>1)?_T("Set"):_T("Not Set"));
	mDlg->m_InfoTree.InsertItem(str,HT_Flag,TVI_LAST);
	str.Format(_T(".......%d = Fin: %s"),(tcpheader->flag&0x01),(1==(tcpheader->flag&0x01))?_T("Set"):_T("Not Set"));
	mDlg->m_InfoTree.InsertItem(str,HT_Flag,TVI_LAST);
	//Window size
	str.Format(_T("Window size value: %d"),ntohs(tcpheader->win));
	mDlg->m_InfoTree.InsertItem(str,HTCP,TVI_LAST);
	//Checksum
	str.Format(_T("Checksum: 0x%04x"),ntohs(tcpheader->checksum));
	mDlg->m_InfoTree.InsertItem(str,HTCP,TVI_LAST);
	//uptr
	if(1==(tcpheader->flag&0x20)>>5)
	{
		str.Format(_T("Urgent point: %d"),ntohs(tcpheader->uptr));
		mDlg->m_InfoTree.InsertItem(str,HTCP,TVI_LAST);
	}
}

void CSnifferDlg::OnCaptureStart()
{
	// TODO: Add your command handler code here
	this->OnBnClickedButton1();
}

void CSnifferDlg::OnCaptureStop()
{
	// TODO: Add your command handler code here
	this->OnBnClickedButton2();
}

void CSnifferDlg::OnCaptureInterface()
{
	// TODO: Add your command handler code here
	INT_PTR nResponse=filter.DoModal();
	if(nResponse==IDOK)
	{
		filterstr=filter.filter;
	}
}

void CSnifferDlg::OnBnClickedButton5()
{
	// TODO: Add your control notification handler code here
	INT_PTR nResponse=filter.DoModal();
	if(nResponse==IDOK)
	{
		filterstr=filter.filter;
	}
}

void CSnifferDlg::OnBnClickedButton4()
{
	// TODO: Add your control notification handler code here
	CFileDialog fDlg(TRUE, _T("(*.CAP)|*.CAP "), _T("*.CAP "),OFN_EXPLORER, _T("Sniffer数据包文件(*.CAP) ")); 
	if(IDOK==fDlg.DoModal())
	{
		CapFilePath=fDlg.GetPathName();
		AfxBeginThread(LoadThread,NULL);
	}
	
}

UINT LoadThread(LPVOID lpParameter)
{/*读取打开的抓包文件*/
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE+1];
	int res;
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	int num=0;
	CString errstring;
	u_int netmask;
	struct bpf_program fcode;

	if(NULL==(adhandle=pcap_open_offline(CStringA(CapFilePath.GetBuffer()),errbuf)))
	{
		CString errstr;
		errstr.Format(_T("Open dump file error,error code:s%"),errbuf);
		AfxMessageBox(errstr);
		return -1;
	}

	netmask=0xffffff; 
	/*char* packet_filter=CFilterDlg::UnicodeToANSI(filterstr.GetBuffer());*/
	if (pcap_compile(adhandle, &fcode, CStringA(filterstr.GetBuffer()), 1, netmask) <0 )
	{
		errstring=CString("Unable to compile the packet filter. Check the syntax.");
		AfxMessageBox(errstring);
		/* 释放设备列表 */
		return -1;
	}

	if (pcap_setfilter(adhandle, &fcode) < 0)
	{
		errstring=CString("Unable to set the filter.Please ensure the expression is correct");
		AfxMessageBox(errstring);
		return -1;
	}
	res = pcap_next_ex( adhandle, &header, &pkt_data);
	while(res  >= 0)
	{
		if(res == 0)
			/* 超时时间到 */
			continue;
		//_itoa(packetNum,list.num,10);
		//sprintf(list.time,timestr);

		//PostMessage(hmainDialog,WM_PACKET_IN,NULL,(LPARAM)pkt);
		/*SendMessageTimeout(hmainDialog,WM_UPDATE_LIST,(WPARAM)&list,0,SMTO_BLOCK,1000,&res);*/
		++num;
		time_t local_tv_sec;
		struct tm *ltime;
		char timestr[16];

		/* 将时间戳转换成可识别的格式 */
		local_tv_sec = header->ts.tv_sec;
		ltime=localtime(&local_tv_sec);
		strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);
		char temp[50];
		_itoa(num,temp,10);
		/*处理以太网首部*/
		ethernet_header *ethheader=(ethernet_header*)pkt_data;
		char protocaltype[10];
		CSnifferDlg::GetEthernetType(ethheader,protocaltype);

		TCHAR srcAddr[18];
		TCHAR desAddr[18];
		/*处理IPv4协议的类型*/
		if(CString(protocaltype)==CString("IPv4"))
		{
			/* 处理IP首部*/
			ip_header *ipheader= (ip_header *)(pkt_data+14); 
			swprintf_s(srcAddr,16,_T("%d.%d.%d.%d"),ipheader->saddr.byte1,ipheader->saddr.byte2,ipheader->saddr.byte3,ipheader->saddr.byte4);
			swprintf_s(desAddr,16,_T("%d.%d.%d.%d"),ipheader->daddr.byte1,ipheader->daddr.byte2,ipheader->daddr.byte3,ipheader->daddr.byte4);
			CSnifferDlg::GetIPv4Type(ipheader,protocaltype);
		}
		if(CString(protocaltype)==CString("ARP"))
		{
			u_char* tmpSrc=ethheader->srcmac;
			u_char* tmpDst=ethheader->dstmac;
			swprintf_s(srcAddr,18,_T("%02X:%02X:%02X:%02X:%02X:%02X"),tmpSrc[0],tmpSrc[1],tmpSrc[2],tmpSrc[3],tmpSrc[4],tmpSrc[5]);
			swprintf_s(desAddr,18,_T("%02X:%02X:%02X:%02X:%02X:%02X"),tmpDst[0],tmpDst[1],tmpDst[2],tmpDst[3],tmpDst[4],tmpDst[5]);
		}

		/*处理包长度*/
		char lenstr[10];
		_itoa(header->len,lenstr,10);
		CSnifferDlg* 	mDlg=((CSnifferDlg*)(AfxGetApp()->GetMainWnd()));
		int i=mDlg->m_List.InsertItem(mDlg->m_List.GetItemCount(),CString(temp));
		//m_List.SetItemText(i,0,CString(list->num));
		//更新listctrl
		mDlg->m_List.SetTextBkColor(0xFFE070);
		mDlg->m_List.SetItemText(i,0,CString(temp));
		mDlg->m_List.SetItemText(i,1,CString(timestr));
		mDlg->m_List.SetItemText(i,2,CString(srcAddr));
		mDlg->m_List.SetItemText(i,3,CString(desAddr));
		mDlg->m_List.SetItemText(i,4,CString(protocaltype));
		mDlg->m_List.SetItemText(i,5,CString(lenstr));
		res = pcap_next_ex( adhandle, &header, &pkt_data);
	}
	return 0;
}
void CSnifferDlg::OnBnClickedButton6()
{
	// TODO: Add your control notification handler code here
	CChartDlg* chartDlg=new CChartDlg;
	
	chartDlg->Create(IDD_CHART_DIALOG,NULL);
	chartDlg->ShowWindow(SW_SHOW);
}



//void CSnifferDlg::OnTimer(UINT_PTR nIDEvent)
//{
//	// TODO: Add your message handler code here and/or call default
//	EnterCriticalSection(&CapThreadCS);
//	tcpnum=0;
//	LeaveCriticalSection(&CapThreadCS);
//	CDialog::OnTimer(nIDEvent);
//}

void CSnifferDlg::OnBnClickedButton3()
{
	// TODO: Add your control notification handler code here
	CFileDialog fDlg(TRUE, _T("(*.CAP)|*.CAP "), _T("*.CAP "),OFN_EXPLORER, _T("Sniffer数据包文件(*.CAP) ")); 
	if(IDOK==fDlg.DoModal())
	{
		CString CapFileSavePath=fDlg.GetPathName();
		CopyFile(CapFilePath,CapFileSavePath,FALSE);
	}
}
