// BypassUAC.cpp : ����Ӧ�ó������ڵ㡣
//

#include "stdafx.h"
#include "BypassUAC.h"
#include <Aclapi.h>
#include <atlpath.h>

// ȫ�ֱ���:
HINSTANCE hInst;                                // ��ǰʵ��
// �˴���ģ���а����ĺ�����ǰ������:
int APIENTRY _tWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPTSTR lpCmdLine,int nCmdShow)
{
	UNREFERENCED_PARAMETER(hPrevInstance);
	UNREFERENCED_PARAMETER(lpCmdLine);
	UNREFERENCED_PARAMETER(nCmdShow);
	hInst = hInstance;
	CPath path(__targv[0]);
	path.RemoveFileSpec();
	if(__argc > 1)
		path.m_strPath = __targv[1];
	if(path.IsRelative())
	{
		CString strPWD;
		DWORD  nSize = ::GetCurrentDirectory(0,NULL);
		::GetCurrentDirectory(nSize,strPWD.GetBuffer(nSize+1));
		strPWD.ReleaseBuffer();
		CString strSub = path.m_strPath;
		path.m_strPath = strPWD;
		path.Append(strSub);
	}
	path.Canonicalize();
	int retVal = 0;
	LPTSTR pszObjName = (LPTSTR)path.m_strPath.GetString();
	SE_OBJECT_TYPE ObjectType = SE_FILE_OBJECT;
	// Get a pointer to the existing DACL.
	PACL pOldDACL = NULL;
	PSECURITY_DESCRIPTOR pSD = NULL;
	DWORD dwRes = GetNamedSecurityInfo(pszObjName, ObjectType, DACL_SECURITY_INFORMATION, NULL, NULL, &pOldDACL, NULL, &pSD);
	if(ERROR_SUCCESS != dwRes)
		retVal = 1;
	else
	{
		EXPLICIT_ACCESS ea;
		ZeroMemory(&ea, sizeof(EXPLICIT_ACCESS));
		ea.grfAccessPermissions = KEY_ALL_ACCESS;
		ea.grfAccessMode = SET_ACCESS;
		ea.grfInheritance= SUB_CONTAINERS_AND_OBJECTS_INHERIT;
		ea.Trustee.TrusteeForm = TRUSTEE_IS_NAME;
		ea.Trustee.ptstrName = _T("Everyone");
		PACL pNewDACL = NULL;
		dwRes = SetEntriesInAcl(1, &ea, pOldDACL, &pNewDACL);
		if(ERROR_SUCCESS != dwRes)
			retVal = 2;
		else
		{
			dwRes = SetNamedSecurityInfo(pszObjName, ObjectType, DACL_SECURITY_INFORMATION, NULL, NULL, pNewDACL, NULL);
			if(ERROR_SUCCESS != dwRes)
				retVal = 3;
		}
		if(pNewDACL != NULL)
			LocalFree((HLOCAL) pNewDACL);
	}
	if(pSD != NULL)
		LocalFree((HLOCAL) pSD);
	CString strMsg,strCaption(_T("UACȨ������"));
	if(retVal == 0)
	{
		strMsg.Format(_T("%s��%s���������ȫ����Ȩ��"),
					  path.IsDirectory()?_T("Ŀ¼"):_T("�ļ�"),
					  path.m_strPath);
		MessageBox(NULL,strMsg,strCaption,MB_OK|MB_ICONINFORMATION);
	}
	else
	{
		LPVOID lpMsgBuf;
		FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
					  NULL, GetLastError(),MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR) &lpMsgBuf, 0, NULL);
		strMsg = (LPCTSTR)lpMsgBuf;
		LocalFree(lpMsgBuf);
		MessageBox(NULL,strMsg,strCaption,MB_OK|MB_ICONERROR);
	}
	return retVal;
}

