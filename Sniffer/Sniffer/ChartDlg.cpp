// ChartDlg.cpp : implementation file
//

#include "stdafx.h"
#include "Sniffer.h"
#include "ChartDlg.h"
#include "SnifferDlg.h"

// CChartDlg dialog

IMPLEMENT_DYNAMIC(CChartDlg, CDialog)

CChartDlg::CChartDlg(CWnd* pParent /*=NULL*/)
	: CDialog(CChartDlg::IDD, pParent)
	, m_Radio(0)
	, chartnum(0)
{

}

CChartDlg::~CChartDlg()
{
}

void CChartDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);

	DDX_Control(pDX, IDC_TCHART1, m_chart);
	DDX_Control(pDX, IDC_CHART_EDIT, m_ChartFilter);
	DDX_Radio(pDX, IDC_RADIO1, m_Radio);
}


BEGIN_MESSAGE_MAP(CChartDlg, CDialog)
//	ON_WM_TIMER()
	ON_WM_CTLCOLOR()
	ON_EN_CHANGE(IDC_CHART_EDIT, &CChartDlg::OnEnChangeChartEdit)
	ON_BN_CLICKED(IDC_CHARTBUTTON, &CChartDlg::OnBnClickedChartbutton)
	ON_WM_CLOSE()
	ON_BN_CLICKED(IDC_RADIO1, &CChartDlg::OnBnClickedRadio1)
	ON_BN_CLICKED(IDC_RADIO2, &CChartDlg::OnBnClickedRadio2)
END_MESSAGE_MAP()


// CChartDlg message handlers

BOOL CChartDlg::OnInitDialog()
{
	CDialog::OnInitDialog();

	// TODO:  Add extra initialization here
// 	m_chart.Series(0).FillSampleValues(50);
// 	m_chart.Series(0).Clear();
// 	m_chart.Series(0).Add(1,_T("0"),1);
// 	m_chart.Series(0).Add(1,_T("0"),1);
	//cDlg=(CChartDlg*)this;
	cDlg=(int)this;
	hbrush=CreateSolidBrush(RGB(255,255,255));
	HasThread=FALSE;
	m_Radio=0;
	chartnum=1;
// 	CString str;
// 	str.Format(_T("%x"),this);
// 		AfxMessageBox(str);
	xtime=0;
	for(int i=0;i<30;i++)
	{
		m_chart.Series(0).Add(0,_T(""),1);
	}
	//SetTimer(1,1000,NULL);
	OnBnClickedChartbutton();
	return TRUE;  // return TRUE unless you set the focus to a control
	// EXCEPTION: OCX Property Pages should return FALSE
}

//void CChartDlg::OnTimer(UINT_PTR nIDEvent)
//{
//	// TODO: Add your message handler code here and/or call default
// 	static int time;
// 	swprintf_s(timestr,256,_T("%s"),time);
// 	time++;
//	//EnterCriticalSection(&CapThreadCS);
//
//	int num;
//	CFile mFile;
//	mFile.Open(_T("num.dat"),CFile::modeRead);
//	CArchive ar(&mFile,CArchive::load);
//	ar>>num;
//
//	m_chart.Series(0).Add(num,_T("a"),1);
//	//LeaveCriticalSection(&CapThreadCS);
//	m_chart.GetAxis().GetBottom().Scroll(1.0,TRUE);
//	/*tcpnum=0;*/
// 	m_chart.GetAxis().GetBottom().Scroll(1.0,TRUE);
//	CDialog::OnTimer(nIDEvent);
//}

UINT TrafficThread(LPVOID lpParameter)
{/*流量统计线程*/
	pcap_if_t* dev=(pcap_if_t*)lpParameter;
	pcap_t *fp;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct timeval st_ts;
	u_int netmask;
	struct bpf_program fcode;
	CString err;
	if((fp= pcap_open(dev->name,100,PCAP_OPENFLAG_PROMISCUOUS,1000,NULL,errbuf))==NULL)
	{

		err.Format(_T("Unable to open the adapter. %s is not supported by WinPcap"),CString(dev->name));
		AfxMessageBox(err);
		pcap_freealldevs(dev);
		//GetDlgItem(IDC_BUTTON1);
		return -1;
	}

	/* 不用关心掩码，在这个过滤器中，它不会被使用 */
	netmask=0xffffff; 

	// 编译过滤器
	if (pcap_compile(fp, &fcode,CStringA(Chartfilter.GetBuffer()) , 1, netmask) <0 )
	{
		err=CString("Unable to compile the packet filter. Check the syntax.");
		AfxMessageBox(err);
		/* 释放设备列表 */
		return -1;
	}

	//设置过滤器
	if (pcap_setfilter(fp, &fcode)<0)
	{
		err=CString("Error setting the filter.");
		AfxMessageBox(err);
		pcap_close(fp);
		/* 释放设备列表 */
		return -1;
	}

	/* 将接口设置为统计模式 */
	if (pcap_setmode(fp, MODE_STAT)<0)
	{
		err=CString("Error setting the mode.");
		AfxMessageBox(err);
		pcap_close(fp);
		/* 释放设备列表 */
		return -1;
	}
	/* 开始主循环 */
	pcap_loop(fp, 0, CChartDlg::dispatcher_handler, (PUCHAR)&st_ts);

	pcap_close(fp);
	return 0;
}
void CChartDlg::dispatcher_handler(u_char *state, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	struct timeval *old_ts = (struct timeval *)state;
    u_int delay;
    LARGE_INTEGER Bps,Pps;
    struct tm *ltime;
    char timestr[16];
    time_t local_tv_sec;

    /* 以毫秒计算上一次采样的延迟时间 */
    /* 这个值通过采样到的时间戳获得 */
    delay=(header->ts.tv_sec - old_ts->tv_sec) * 1000000 - old_ts->tv_usec + header->ts.tv_usec;
    /* 获取每秒的比特数b/s */
    Bps.QuadPart=(((*(LONGLONG*)(pkt_data + 8)) * 8 * 1000000) / (delay));
    /*                                            ^      ^
                                                  |      |
                                                  |      | 
                                                  |      |
                              将字节转换成比特 -- |
                                                         |
                                       延时是以毫秒表示的 --
    */

    /* 得到每秒的数据包数量 */
    Pps.QuadPart=(((*(LONGLONG*)(pkt_data)) * 1000000) / (delay));

    /* 将时间戳转化为可识别的格式 */
    local_tv_sec = header->ts.tv_sec;
    ltime=localtime(&local_tv_sec);
    strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);
	//CChartDlg* cDlg=(CChartDlg*)FindWindow(_T("CChartDlg"),NULL);
// 	CString str;
// 	str.Format(_T("%x"),cDlg);
// 	AfxMessageBox(str);
	TCHAR xstr[64];
	swprintf_s(xstr,64,_T("%d"),xtime);
	xtime++;
	if(BST_CHECKED==((CChartDlg*)cDlg)->IsDlgButtonChecked(IDC_RADIO1))
		((CChartDlg*)cDlg)->m_chart.Series(0).Add(Bps.QuadPart/8,xstr,1);
 	else
 		((CChartDlg*)cDlg)->m_chart.Series(0).Add(Pps.QuadPart,xstr,1);
	old_ts->tv_sec=header->ts.tv_sec;
	old_ts->tv_usec=header->ts.tv_usec;

}
HBRUSH CChartDlg::OnCtlColor(CDC* pDC, CWnd* pWnd, UINT nCtlColor)
{
	HBRUSH hbr = CDialog::OnCtlColor(pDC, pWnd, nCtlColor);
	if (pWnd-> GetDlgCtrlID()==IDC_CHART_EDIT)
	{ 
		//pDC-> SetTextColor(RGB(255,0,0)); //设置字体颜色
		pDC-> SetBkMode(TRANSPARENT); //设置字体背景为透明
		// TODO: Return a different brush if the default is not desired
		return hbrush; // 设置背景色
	} 
	else
	// TODO:  Change any attributes of the DC here

	// TODO:  Return a different brush if the default is not desired
	return hbr;
}

void CChartDlg::OnEnChangeChartEdit()
{
	// TODO:  If this is a RICHEDIT control, the control will not
	// send this notification unless you override the CDialog::OnInitDialog()
	// function and call CRichEditCtrl().SetEventMask()
	// with the ENM_CHANGE flag ORed into the mask.
	bpf_program fcode;
	GetDlgItemText(IDC_CHART_EDIT,Chartfilter);
	if(0==pcap_compile_nopcap(65536,DLT_EN10MB,&fcode,/*filterstr*/CStringA(Chartfilter.GetBuffer()),1,0xffffff))
	{
		hbrush=CreateSolidBrush(RGB(175,255,175));
		m_ChartFilter.Invalidate();
	}
	else
	{
		hbrush=CreateSolidBrush(RGB(255,175,175));
		m_ChartFilter.Invalidate();
	}
	// TODO:  Add your control notification handler code here
}

void CChartDlg::OnBnClickedChartbutton()
{
	// TODO: Add your control notification handler code here

	CSnifferDlg* mDlg;
	bpf_program fcode;
	mDlg=((CSnifferDlg*)(AfxGetApp()->GetMainWnd()));
	GetDlgItemText(IDC_CHART_EDIT,Chartfilter);
	if(0==pcap_compile_nopcap(65536,DLT_EN10MB,&fcode,/*filterstr*/CStringA(Chartfilter.GetBuffer()),1,0xffffff))
	{
		xtime=0;
		m_chart.Series(0).Clear();
		for(int i=0;i<30;i++)
		{
			m_chart.Series(0).Add(0,_T(""),1);
		}
		if(HasThread)
			TerminateThread(hTrafficThread->m_hThread,2);
		hTrafficThread=AfxBeginThread(TrafficThread,LPVOID(mDlg->d));
		HasThread=TRUE;
	}
	else
	{
		AfxMessageBox(_T("Filter String is error,please check!"));
		return;
	}
}

void CChartDlg::OnClose()
{
	// TODO: Add your message handler code here and/or call default
	if(HasThread)
	{
		TerminateThread(hTrafficThread->m_hThread,2);
		HasThread=FALSE;
	}
	CDialog::OnClose();
}


void CChartDlg::OnBnClickedRadio1()
{
	// TODO: Add your control notification handler code here
	if(1==chartnum)
		return;
	xtime=0;
	chartnum=1;
	m_chart.Series(0).Clear();
	for(int i=0;i<30;i++)
	{
		m_chart.Series(0).Add(0,_T(""),1);
	}
	
}

void CChartDlg::OnBnClickedRadio2()
{
	// TODO: Add your control notification handler code here
	if(2==chartnum)
		return;
	xtime=0;
	m_chart.Series(0).Clear();
	for(int i=0;i<30;i++)
	{
		m_chart.Series(0).Add(0,_T(""),1);
	}
	chartnum=2;
}
