#include "stdafx.h"
#include "ProcEnrich.h"

#include <winternl.h>
#include <wintrust.h>
#include <Softpub.h>
#include <sddl.h>
#include <wtsapi32.h>

#pragma comment(lib, "version.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "wtsapi32.lib")

// ---------- UserName ----------

static CString SidToAccountName(PSID sid)
{
    CString out = _T("-");
    if (!sid) return out;

    WCHAR user[128] = { 0 };
    WCHAR dom[128] = { 0 };
    DWORD cu = _countof(user), cd = _countof(dom);
    SID_NAME_USE su;
    if (LookupAccountSidW(NULL, sid, user, &cu, dom, &cd, &su)) {
        if (cd > 0) out.Format(_T("%s\\%s"), dom, user);
        else        out = user;
    }
    return out;
}

static CString GetProcessUserNameByToken(DWORD pid)
{
    HANDLE hp = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hp) return _T("-");
    HANDLE ht = NULL;
    CString out = _T("-");
    do {
        if (!OpenProcessToken(hp, TOKEN_QUERY, &ht)) break;
        DWORD need = 0;
        GetTokenInformation(ht, TokenUser, NULL, 0, &need);
        if (need == 0) break;
        std::vector<BYTE> buf(need);
        if (!GetTokenInformation(ht, TokenUser, buf.data(), need, &need)) break;
        TOKEN_USER* tu = (TOKEN_USER*)buf.data();
        out = SidToAccountName(tu->User.Sid);
    } while (0);
    if (ht) CloseHandle(ht);
    CloseHandle(hp);
    return out;
}

static CString GetProcessUserNameByWts(DWORD pid)
{
    DWORD level = 1;
    DWORD count = 0;
    PWTS_PROCESS_INFO_EXW info = NULL;
    CString out = _T("-");

    if (WTSEnumerateProcessesExW(WTS_CURRENT_SERVER_HANDLE,
                                 &level,
                                 WTS_ANY_SESSION,
                                 (LPWSTR*)&info,
                                 &count))
    {
        for (DWORD i = 0; i < count; ++i) {
            if (info[i].ProcessId == pid) {
                out = SidToAccountName(info[i].pUserSid);
                break;
            }
        }
        WTSFreeMemoryExW(WTSTypeProcessInfoLevel1, info, count);
    }
    return out;
}

CString ArkGetProcessUserName(DWORD pid)
{
    if (pid == 0 || pid == 4) return _T("SYSTEM");

    CString out = GetProcessUserNameByToken(pid);
    if (out == _T("-")) {
        out = GetProcessUserNameByWts(pid);
    }
    return out;
}

// ---------- FileVendor (CompanyName from version info) ----------

static CString GetFileVendor(LPCTSTR path)
{
    if (!path || !*path || _tcscmp(path, _T("-")) == 0) return _T("-");

    DWORD dummy = 0;
    DWORD sz = GetFileVersionInfoSize(path, &dummy);
    if (sz == 0) return _T("-");
    std::vector<BYTE> data(sz);
    if (!GetFileVersionInfo(path, 0, sz, data.data())) return _T("-");

    struct LANGCODE { WORD wLang; WORD wCode; } *trans = nullptr;
    UINT trLen = 0;
    if (!VerQueryValue(data.data(), _T("\\VarFileInfo\\Translation"),
                       (LPVOID*)&trans, &trLen) || trLen < sizeof(LANGCODE))
        return _T("-");

    CString sub;
    sub.Format(_T("\\StringFileInfo\\%04x%04x\\CompanyName"),
               trans[0].wLang, trans[0].wCode);
    LPTSTR vstr = nullptr; UINT vlen = 0;
    if (!VerQueryValue(data.data(), sub.GetBuffer(), (LPVOID*)&vstr, &vlen)
        || vlen == 0)
    {
        sub.ReleaseBuffer();
        return _T("-");
    }
    sub.ReleaseBuffer();
    return CString(vstr);
}

// ---------- Signature ----------

static CString GetFileSignStatus(LPCTSTR path)
{
    if (!path || !*path || _tcscmp(path, _T("-")) == 0) return _T("-");

    WINTRUST_FILE_INFO fi = { 0 };
    fi.cbStruct       = sizeof(fi);
    fi.pcwszFilePath  = path;

    GUID policyGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA wd = { 0 };
    wd.cbStruct            = sizeof(wd);
    wd.dwUIChoice          = WTD_UI_NONE;
    wd.fdwRevocationChecks = WTD_REVOKE_NONE;
    wd.dwUnionChoice       = WTD_CHOICE_FILE;
    wd.pFile               = &fi;
    wd.dwStateAction       = WTD_STATEACTION_VERIFY;
    wd.dwProvFlags         = WTD_SAFER_FLAG | WTD_CACHE_ONLY_URL_RETRIEVAL;

    LONG r = WinVerifyTrust(NULL, &policyGuid, &wd);

    wd.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &policyGuid, &wd);

    return (r == ERROR_SUCCESS) ? CString(_T("Signed"))
                                : CString(_T("Unsigned"));
}

// ---------- CommandLine via NtQueryInformationProcess(ProcessCommandLineInformation=60) ----------

typedef NTSTATUS (NTAPI *PFN_NtQIP)(
    HANDLE, ULONG, PVOID, ULONG, PULONG);

#ifndef ProcessCommandLineInformation
#define ProcessCommandLineInformation 60
#endif

CString ArkGetProcessCommandLine(DWORD pid)
{
    static PFN_NtQIP pNtQIP = (PFN_NtQIP)
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"),
                       "NtQueryInformationProcess");
    if (!pNtQIP) return _T("-");

    HANDLE hp = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hp) return _T("-");

    CString out = _T("-");
    ULONG need = 0;
    pNtQIP(hp, ProcessCommandLineInformation, NULL, 0, &need);
    if (need >= sizeof(UNICODE_STRING)) {
        std::vector<BYTE> buf(need);
        if (pNtQIP(hp, ProcessCommandLineInformation, buf.data(), need, &need) == 0) {
            UNICODE_STRING* us = (UNICODE_STRING*)buf.data();
            if (us->Buffer && us->Length > 0) {
                out = CString(us->Buffer, us->Length / sizeof(WCHAR));
            }
        }
    }
    CloseHandle(hp);
    return out;
}

// ---------- entry point ----------

void ArkEnrichProcess(DWORD pid, LPCTSTR imagePath, ArkEnrich& out)
{
    if (pid == 0) {                    // Idle
        out.UserName = _T("SYSTEM");
        out.FileVendor = _T("-");
        out.SignStatus = _T("-");
        out.CommandLine = _T("-");
        return;
    }
    if (pid == 4) {                    // System
        out.UserName = _T("SYSTEM");
        out.FileVendor = _T("Microsoft Corporation");
        out.SignStatus = _T("-");
        out.CommandLine = _T("-");
        return;
    }
    out.UserName    = ArkGetProcessUserName(pid);
    out.FileVendor  = GetFileVendor(imagePath);
    out.SignStatus  = GetFileSignStatus(imagePath);
    out.CommandLine = ArkGetProcessCommandLine(pid);
}
