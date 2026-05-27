#pragma once

#include <windows.h>
#include <string>

struct ArkEnrich
{
    CString UserName;        // "domain\\user"
    CString FileVendor;      // CompanyName from version info
    CString SignStatus;      // "已签名" / "未签名" / "-"
    CString CommandLine;     // raw cmdline of process
};

//
// Best-effort enrichment for a single process. Failures degrade to "-".
// pid and imagePath are inputs; pid==0/4 are special-cased.
//
void ArkEnrichProcess(DWORD pid, LPCTSTR imagePath, ArkEnrich& out);

CString ArkGetProcessUserName(DWORD pid);
CString ArkGetProcessCommandLine(DWORD pid);
