#pragma once
#include "afxwin.h"
#include "MyPcap.h"


// CFilterDlg dialog


class CFilterDlg : public CDialog
{
	DECLARE_DYNAMIC(CFilterDlg)

public:
	CFilterDlg(CWnd* pParent = NULL);   // standard constructor
	virtual ~CFilterDlg();

// Dialog Data
	enum { IDD = IDD_FILTER_DIALOG };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

	DECLARE_MESSAGE_MAP()
public:
	_ConnectionPtr   m_pConnection; // 数据库 
	_RecordsetPtr    m_pRecordset; // 命令 
	_CommandPtr      m_pCommand; // 记录
	void OnInitADOConn();//连接数据库
	void ExitConnect();
	virtual BOOL OnInitDialog();
	void ReadFilter(void);
	CListBox m_filterList;
	afx_msg void OnLbnSelchangeList1();
	CEdit m_filterName;
	CEdit m_filterString;
	afx_msg void OnBnClickedButton4();
	afx_msg void OnBnClickedButton3();
	BOOL HasNewFilter;
	int LastSel;
	struct bpf_program fcode;
	afx_msg void OnEnChangeEdit2();
	static char* UnicodeToANSI( WCHAR* str );
	afx_msg HBRUSH OnCtlColor(CDC* pDC, CWnd* pWnd, UINT nCtlColor);
	HBRUSH hbrush;
	afx_msg void OnBnClickedButton2();
	afx_msg void OnBnClickedButton1();
	CString filter;
	afx_msg void OnClose();
};
