// FilterDlg.cpp : implementation file
//

#include "stdafx.h"
#include "Sniffer.h"
#include "FilterDlg.h"


// CFilterDlg dialog

IMPLEMENT_DYNAMIC(CFilterDlg, CDialog)

CFilterDlg::CFilterDlg(CWnd* pParent /*=NULL*/)
	: CDialog(CFilterDlg::IDD, pParent)
	, HasNewFilter(FALSE)
	, LastSel(0)
{

}

CFilterDlg::~CFilterDlg()
{
}

void CFilterDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST1, m_filterList);
	DDX_Control(pDX, IDC_EDIT1, m_filterName);
	DDX_Control(pDX, IDC_EDIT2, m_filterString);
}


BEGIN_MESSAGE_MAP(CFilterDlg, CDialog)
	//ON_LBN_SELCHANGE(IDC_LIST1, &CFilterDlg::OnLbnSelchangeList1)
	ON_LBN_SELCHANGE(IDC_LIST1, &CFilterDlg::OnLbnSelchangeList1)
	ON_BN_CLICKED(IDC_BUTTON4, &CFilterDlg::OnBnClickedButton4)
	ON_BN_CLICKED(IDC_BUTTON3, &CFilterDlg::OnBnClickedButton3)
	ON_EN_CHANGE(IDC_EDIT2, &CFilterDlg::OnEnChangeEdit2)
	ON_WM_CTLCOLOR()
	ON_BN_CLICKED(IDC_BUTTON2, &CFilterDlg::OnBnClickedButton2)
	ON_BN_CLICKED(IDC_BUTTON1, &CFilterDlg::OnBnClickedButton1)
	ON_WM_CLOSE()
END_MESSAGE_MAP()


// CFilterDlg message handlers
void CFilterDlg::OnInitADOConn()
{
	::CoInitialize(NULL);
	try
	{
		m_pConnection.CreateInstance("ADODB.Connection");
		_bstr_t strConnect="Provider=Microsoft.Jet.OLEDB.4.0;Data Source=filter.mdb";//Home.mdb放在工程目录下   
		m_pConnection->Open(strConnect,"","",adModeUnknown);
		//AfxMessageBox(_T("连接成功"));
	}
	catch(_com_error e)
	{
		AfxMessageBox(_T("数据库filter.mdb打开失败！"));
	}
}
void CFilterDlg::ExitConnect()
{
	if(m_pRecordset!=NULL)
		m_pRecordset->Close();
	m_pConnection->Close();
	::CoUninitialize();
}
BOOL CFilterDlg::OnInitDialog()
{
	CDialog::OnInitDialog();

	// TODO:  Add extra initialization here
	HasNewFilter=FALSE;
	LastSel=-1;
	hbrush=CreateSolidBrush(RGB(255,255,255));
	this->OnInitADOConn();//连接access数据库
	this->ReadFilter();//读取数据库中的filter sample
	return TRUE;  // return TRUE unless you set the focus to a control
	// EXCEPTION: OCX Property Pages should return FALSE
}

void CFilterDlg::ReadFilter(void)
{
	_variant_t vFilterName,vFilterString;
	m_pRecordset.CreateInstance("ADODB.Recordset");
	m_pRecordset->Open("SELECT * FROM Filter ORDER BY num",_variant_t((IDispatch*)m_pConnection,true),adOpenStatic,adLockOptimistic,adCmdText);
	m_pRecordset->MoveFirst();
	while(!m_pRecordset->adoEOF)
	{
		vFilterName=m_pRecordset->GetCollect(_variant_t((long)0));
		vFilterString=m_pRecordset->GetCollect(_variant_t((long)1));
		m_filterList.InsertString(m_filterList.GetCount(),(LPCTSTR)(_bstr_t)vFilterName);
		//AfxMessageBox((LPCTSTR)(_bstr_t)vFilterName);
		m_pRecordset->MoveNext();
	}
}



void CFilterDlg::OnLbnSelchangeList1()
{
	// TODO: Add your control notification handler code here
	CString Filtername,Filterstring;
	GetDlgItemText(IDC_EDIT1,Filtername);
	GetDlgItemText(IDC_EDIT2,Filterstring);
	if(HasNewFilter==TRUE)
	{
		m_pRecordset->MoveLast();
		m_pRecordset->AddNew();
		CString Filtername,Filterstring;
		GetDlgItemText(IDC_EDIT1,Filtername);
		GetDlgItemText(IDC_EDIT2,Filterstring);
		m_filterList.DeleteString(m_filterList.GetCount()-1);
		m_filterList.InsertString(m_filterList.GetCount(),Filtername);
		m_pRecordset->PutCollect(_variant_t((long)0),_variant_t(Filtername));
		m_pRecordset->PutCollect(_variant_t((long)1),_variant_t(Filterstring));
		m_pRecordset->Update();
		HasNewFilter=FALSE;
	}
	_variant_t vFilterName,vFilterString;
// 	if(LastSel!=-1)
// 	{
// 		m_pRecordset->Move(LastSel,_variant_t((long)adBookmarkFirst));
// 		m_pRecordset->PutCollect(_variant_t((long)0),_variant_t(Filtername));
// 		m_pRecordset->PutCollect(_variant_t((long)1),_variant_t(Filterstring));
// 		m_pRecordset->Update();
// 		m_filterList.DeleteString(LastSel);
// 		m_filterList.InsertString(LastSel,Filtername);
// 
// 	}

	int num=m_filterList.GetCurSel();
/*	LastSel=num;*/
	if(LB_ERR==num)
	{
		AfxMessageBox(_T("None Select!"));
		return;
	}
	m_pRecordset->Move(num,_variant_t((long)adBookmarkFirst));
	vFilterName=m_pRecordset->GetCollect(_variant_t((long)0));
	vFilterString=m_pRecordset->GetCollect(_variant_t((long)1));
	SetDlgItemText(IDC_EDIT1,(LPCTSTR)(_bstr_t)vFilterName);
	SetDlgItemText(IDC_EDIT2,(LPCTSTR)(_bstr_t)vFilterString);
}

void CFilterDlg::OnBnClickedButton4()//删除
{
	// TODO: Add your control notification handler code here
	_variant_t vFilterName,vFilterString;
	int num=m_filterList.GetCurSel();
	if(LB_ERR==num)
	{
		AfxMessageBox(_T("None Select!Can't Delete"));
		return;
	}
	m_pRecordset->Move(num,_variant_t((long)adBookmarkFirst));
	m_pRecordset->Delete(adAffectCurrent);
	m_filterList.DeleteString(num);

}

void CFilterDlg::OnBnClickedButton3()
{
	// TODO: Add your control notification handler code here
	if(HasNewFilter==TRUE)
	{
		m_pRecordset->MoveLast();
		m_pRecordset->AddNew();
		CString Filtername,Filterstring;
		GetDlgItemText(IDC_EDIT1,Filtername);
		GetDlgItemText(IDC_EDIT2,Filterstring);
		m_filterList.DeleteString(m_filterList.GetCount()-1);
		m_filterList.InsertString(m_filterList.GetCount(),Filtername);
		m_pRecordset->PutCollect(_variant_t((long)0),_variant_t(Filtername));
		m_pRecordset->PutCollect(_variant_t((long)1),_variant_t(Filterstring));
		m_pRecordset->Update();
	}
	m_filterList.InsertString(m_filterList.GetCount(),_T("new"));
	m_filterList.SetCurSel(m_filterList.GetCount()-1);
	SetDlgItemText(IDC_EDIT1,_T("new"));
	SetDlgItemText(IDC_EDIT2,_T("new"));
	HasNewFilter=TRUE;

}

void CFilterDlg::OnEnChangeEdit2()
{//判断输入的filter string 是否合法
	// TODO:  If this is a RICHEDIT control, the control will not
	// send this notification unless you override the CDialog::OnInitDialog()
	// function and call CRichEditCtrl().SetEventMask()
	// with the ENM_CHANGE flag ORed into the mask.

	// TODO:  Add your control notification handler code here
	//CString filter;
	GetDlgItemText(IDC_EDIT2,filter);
	/*char* filterstr=UnicodeToANSI(filter.GetBuffer());*/
	if(0==pcap_compile_nopcap(65536,DLT_EN10MB,&fcode,/*filterstr*/CStringA(filter.GetBuffer()),1,0xffffff))
	{
		hbrush=CreateSolidBrush(RGB(175,255,175));
		m_filterString.Invalidate();
 	}
	else
	{
		hbrush=CreateSolidBrush(RGB(255,175,175));
		m_filterString.Invalidate();
	}
}
char* CFilterDlg::UnicodeToANSI( WCHAR* str )
{
	char*     pElementText;
	int    iTextLen;
	// wide char to multi char
	iTextLen = WideCharToMultiByte( CP_ACP,0,str,-1,NULL,0,NULL,NULL );
	pElementText = new char[iTextLen + 1];
	memset( ( void* )pElementText, 0, sizeof( char ) * ( iTextLen + 1 ) );
	::WideCharToMultiByte( CP_ACP,0,str,-1,pElementText,iTextLen,NULL,NULL );
	return pElementText;
}



HBRUSH CFilterDlg::OnCtlColor(CDC* pDC, CWnd* pWnd, UINT nCtlColor)
{//重画editctrl的背景色
	HBRUSH hbr = CDialog::OnCtlColor(pDC, pWnd, nCtlColor);

	// TODO:  Change any attributes of the DC here
	if (pWnd-> GetDlgCtrlID()==IDC_EDIT2)
	{ 
		//pDC-> SetTextColor(RGB(255,0,0)); //设置字体颜色
		pDC-> SetBkMode(TRANSPARENT); //设置字体背景为透明
		// TODO: Return a different brush if the default is not desired
		return hbrush; // 设置背景色
	} 
	else
	// TODO:  Return a different brush if the default is not desired
	return hbr;
}

void CFilterDlg::OnBnClickedButton2()
{
	// TODO: Add your control notification handler code here
	CDialog::OnCancel();
	
}

void CFilterDlg::OnBnClickedButton1()
{
	// TODO: Add your control notification handler code here
	//CString filter;
	GetDlgItemText(IDC_EDIT2,filter);
	/*char* filterstr=UnicodeToANSI(filter.GetBuffer());*/
	if(0==pcap_compile_nopcap(65536,DLT_EN10MB,&fcode,/*filterstr*/CStringA(filter.GetBuffer()),1,0xffffff))
	{
		CDialog::OnOK();
	}
	else
	{
		CString err;
		err.Format(_T("The filter \"%s\" is not a valid filter,please re-enter!"),filter);
		AfxMessageBox(err);
		return;
	}
}
// CString CFilterDlg::Getfilter()
// {
// 	return filter;
// }

void CFilterDlg::OnClose()
{
	// TODO: Add your message handler code here and/or call default
	ExitConnect();
	CDialog::OnClose();
}
