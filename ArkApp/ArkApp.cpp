#include "stdafx.h"
#include "ArkApp.h"
#include "ArkDlg.h"
#include "ProcEnrich.h"
#include "../NetDrv/Ioctl.h"

#include <cstdarg>
#include <TlHelp32.h>
#include <Wbemidl.h>

#pragma comment(lib, "wbemuuid.lib")

CArkApp theApp;

static void AgentLog(LPCTSTR format, ...)
{
#if 0  /* logging disabled */

    SYSTEMTIME st;
    GetLocalTime(&st);

    CString line;
    line.Format(_T("%04u-%02u-%02u %02u:%02u:%02u.%03u %s\r\n"),
                st.wYear, st.wMonth, st.wDay,
                st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
                (LPCTSTR)message);
    OutputDebugString(_T("[ScreenAgent] "));
    OutputDebugString(line);

    TCHAR exePath[MAX_PATH] = { 0 };
    GetModuleFileName(NULL, exePath, MAX_PATH);
    CString path(exePath);
    int slash = path.ReverseFind(_T('\\'));
    path = slash >= 0 ? path.Left(slash + 1) : CString();
    path += _T("screenagent.log");

    HANDLE file = CreateFile(path, FILE_APPEND_DATA,
                             FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                             OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) return;

    CStringW wideLine(line);
    int bytesNeeded = WideCharToMultiByte(CP_UTF8, 0,
                                          wideLine, wideLine.GetLength(),
                                          NULL, 0, NULL, NULL);
    if (bytesNeeded > 0) {
        std::vector<char> utf8((size_t)bytesNeeded);
        WideCharToMultiByte(CP_UTF8, 0,
                            wideLine, wideLine.GetLength(),
                            utf8.data(), bytesNeeded, NULL, NULL);
        DWORD written = 0;
        WriteFile(file, utf8.data(), (DWORD)utf8.size(), &written, NULL);
    }
    CloseHandle(file);
#endif  /* logging disabled */
}

static bool AgentSendPacket(SOCKET sock,
                            const sockaddr_in& peer,
                            const char* payload,
                            int payloadLen)
{
    if (payloadLen <= 0 || payloadLen > 65000) return false;

    std::vector<char> packet((size_t)NETDRV_UDP_PACKET_MAGIC_LEN + payloadLen);
    int packetLen = NETDRV_UDP_PACKET_MAGIC_LEN + payloadLen;
    memcpy(packet.data(), NETDRV_UDP_PACKET_MAGIC, NETDRV_UDP_PACKET_MAGIC_LEN);
    memcpy(packet.data() + NETDRV_UDP_PACKET_MAGIC_LEN, payload, payloadLen);
    return sendto(sock, packet.data(), packetLen, 0,
                  (const sockaddr*)&peer, sizeof(peer)) == packetLen;
}

static sockaddr_in AgentAppPeer();

static bool AgentSendFrame(SOCKET sock,
                           const sockaddr_in& peer,
                           UINT frameId,
                           int width,
                           int height,
                           const BYTE* pixels,
                           size_t bytes)
{
    if (!pixels || bytes == 0) return false;

    const UINT chunkSize = 512;
    UINT chunkCount = (UINT)((bytes + chunkSize - 1) / chunkSize);

    CStringA header;
    header.Format("B|shot|%u|%d|%d|%I64X|%u|%u\n",
                  frameId, width, height, (ULONGLONG)bytes, chunkSize, chunkCount);
    if (!AgentSendPacket(sock, peer, header, header.GetLength())) return false;

    static const char kHex[] = "0123456789ABCDEF";
    std::vector<char> payload(chunkSize * 2 + 96);
    for (UINT i = 0; i < chunkCount; ++i) {
        size_t off = (size_t)i * chunkSize;
        UINT len = (UINT)(((bytes - off) > chunkSize) ? chunkSize : (bytes - off));

        int prefixLen = _snprintf_s(payload.data(), payload.size(), _TRUNCATE,
                        "Y|%u|%u|%I64X|%X|", frameId, i, (ULONGLONG)off, len);
        if (prefixLen <= 0) return false;

        char* dst = payload.data() + prefixLen;
        for (UINT k = 0; k < len; ++k) {
            BYTE b = pixels[off + k];
            *dst++ = kHex[(b >> 4) & 0xF];
            *dst++ = kHex[b & 0xF];
        }
        *dst++ = '\n';

        if (!AgentSendPacket(sock, peer, payload.data(), (int)(dst - payload.data()))) return false;
        if ((i & 0x0F) == 0x0F) Sleep(1);
    }

    CStringA trailer;
    trailer.Format("E|shot|%u|%I64u\n", frameId, (ULONGLONG)bytes);
    return AgentSendPacket(sock, peer, trailer, trailer.GetLength());
}

static bool AgentStringLooksRemote(LPCWSTR text)
{
    if (!text || !*text) return false;
    CString s(text);
    s.MakeLower();
    return s.Find(_T("remote")) >= 0 ||
           s.Find(_T("rdp")) >= 0 ||
           s.Find(_T("termdd")) >= 0 ||
           s.Find(_T("hyper-v")) >= 0 ||
           s.Find(_T("vmconnect")) >= 0;
}

struct AgentMonitorPick
{
    bool remoteSession = false;
    HMONITOR cursorMonitor = NULL;
    bool found = false;
    RECT rc = { 0, 0, 0, 0 };
    bool primary = false;
    bool remoteLike = false;
    LONGLONG score = 0;
    CString device;
    CString name;
};

static LONGLONG AgentMonitorArea(const RECT& rc)
{
    LONG width = rc.right - rc.left;
    LONG height = rc.bottom - rc.top;
    if (width < 0) width = 0;
    if (height < 0) height = 0;
    return (LONGLONG)width * height;
}

static BOOL CALLBACK AgentEnumMonitorProc(HMONITOR monitor, HDC, LPRECT, LPARAM param)
{
    AgentMonitorPick* pick = (AgentMonitorPick*)param;
    MONITORINFOEXW mi = {};
    mi.cbSize = sizeof(mi);
    if (!GetMonitorInfoW(monitor, &mi)) return TRUE;

    DISPLAY_DEVICEW dd = {};
    dd.cb = sizeof(dd);
    EnumDisplayDevicesW(mi.szDevice, 0, &dd, 0);

    bool primary = (mi.dwFlags & MONITORINFOF_PRIMARY) != 0;
    bool remoteLike = AgentStringLooksRemote(mi.szDevice) || AgentStringLooksRemote(dd.DeviceString);
    LONGLONG area = AgentMonitorArea(mi.rcMonitor);
    LONGLONG score = area;
    if (monitor == pick->cursorMonitor) score += 1000000000LL;
    if (pick->remoteSession && remoteLike) score += 100000000LL;
    if (primary) score += 10000000LL;

    if (!pick->found || score > pick->score) {
        pick->found = true;
        pick->rc = mi.rcMonitor;
        pick->primary = primary;
        pick->remoteLike = remoteLike;
        pick->score = score;
        pick->device = mi.szDevice;
        pick->name = dd.DeviceString;
    }

    return TRUE;
}

static bool AgentChooseCaptureMonitor(RECT& rc, CString& name)
{
    AgentMonitorPick pick;
    pick.remoteSession = GetSystemMetrics(SM_REMOTESESSION) != 0;

    POINT cursor = {};
    if (GetCursorPos(&cursor)) {
        pick.cursorMonitor = MonitorFromPoint(cursor, MONITOR_DEFAULTTONULL);
    }

    EnumDisplayMonitors(NULL, NULL, AgentEnumMonitorProc, (LPARAM)&pick);
    if (pick.found && AgentMonitorArea(pick.rc) > 0) {
        rc = pick.rc;
        name.Format(_T("%s %s primary=%d remoteSession=%d remoteLike=%d"),
                    (LPCTSTR)pick.device, (LPCTSTR)pick.name,
                    pick.primary ? 1 : 0,
                    pick.remoteSession ? 1 : 0,
                    pick.remoteLike ? 1 : 0);
        return true;
    }

    rc.left = 0;
    rc.top = 0;
    rc.right = GetSystemMetrics(SM_CXSCREEN);
    rc.bottom = GetSystemMetrics(SM_CYSCREEN);
    name = _T("SM_CXSCREEN/SM_CYSCREEN fallback");
    return rc.right > rc.left && rc.bottom > rc.top;
}

static bool AgentCapturePrimaryScreen(std::vector<BYTE>& pixels, int& outW, int& outH, RECT* sourceRect, CString* sourceName)
{
    RECT src = {};
    CString monitorName;
    if (!AgentChooseCaptureMonitor(src, monitorName)) return false;

    int srcW = src.right - src.left;
    int srcH = src.bottom - src.top;
    if (srcW <= 0 || srcH <= 0) return false;

    outW = 320;
    outH = (srcH * outW + srcW / 2) / srcW;
    if (outH <= 0) outH = 1;

    HDC screenDc = GetDC(NULL);
    if (!screenDc) return false;
    HDC memDc = CreateCompatibleDC(screenDc);
    if (!memDc) {
        ReleaseDC(NULL, screenDc);
        return false;
    }

    BITMAPINFO bi = {};
    bi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bi.bmiHeader.biWidth = outW;
    bi.bmiHeader.biHeight = -outH;
    bi.bmiHeader.biPlanes = 1;
    bi.bmiHeader.biBitCount = 32;
    bi.bmiHeader.biCompression = BI_RGB;

    void* bits = NULL;
    HBITMAP dib = CreateDIBSection(screenDc, &bi, DIB_RGB_COLORS, &bits, NULL, 0);
    if (!dib || !bits) {
        if (dib) DeleteObject(dib);
        DeleteDC(memDc);
        ReleaseDC(NULL, screenDc);
        return false;
    }

    HGDIOBJ old = SelectObject(memDc, dib);
    SetStretchBltMode(memDc, HALFTONE);
    SetBrushOrgEx(memDc, 0, 0, NULL);
    BOOL ok = StretchBlt(memDc, 0, 0, outW, outH,
                         screenDc, src.left, src.top, srcW, srcH,
                         SRCCOPY | CAPTUREBLT);

    pixels.assign((BYTE*)bits, (BYTE*)bits + ((size_t)outW * outH * 4));
    SelectObject(memDc, old);
    DeleteObject(dib);
    DeleteDC(memDc);
    ReleaseDC(NULL, screenDc);
    if (sourceRect) *sourceRect = src;
    if (sourceName) *sourceName = monitorName;
    return ok == TRUE;
}

static DWORD WINAPI AgentCaptureThreadProc(LPVOID context)
{
    SOCKET sock = (SOCKET)(UINT_PTR)context;
    sockaddr_in peer = AgentAppPeer();
    UINT frameId = 1;

    for (;;) {
        std::vector<BYTE> pixels;
        int width = 0;
        int height = 0;
        RECT sourceRect = {};
        CString sourceName;
        if (AgentCapturePrimaryScreen(pixels, width, height, &sourceRect, &sourceName)) {
            bool ok = AgentSendFrame(sock, peer, frameId, width, height, pixels.data(), pixels.size());
            if ((frameId & 0x0F) == 1) {
                AgentLog(_T("screen frame id=%u src=(%ld,%ld)-(%ld,%ld) %s out=%dx%d bytes=%Iu ok=%d"),
                         frameId,
                         sourceRect.left, sourceRect.top, sourceRect.right, sourceRect.bottom,
                         (LPCTSTR)sourceName,
                         width, height, pixels.size(), ok ? 1 : 0);
            }
            ++frameId;
        } else {
            AgentLog(_T("screen capture failed err=%u"), GetLastError());
        }
        Sleep(700);
    }
}

static sockaddr_in AgentAppPeer()
{
    sockaddr_in peer = { 0 };
    peer.sin_family = AF_INET;
    peer.sin_port = htons(NETDRV_UDP_PORT);
    peer.sin_addr.S_un.S_un_b.s_b1 = NETDRV_APP_IP_B1;
    peer.sin_addr.S_un.S_un_b.s_b2 = NETDRV_APP_IP_B2;
    peer.sin_addr.S_un.S_un_b.s_b3 = NETDRV_APP_IP_B3;
    peer.sin_addr.S_un.S_un_b.s_b4 = NETDRV_APP_IP_B4;
    return peer;
}

static CStringA Utf8HexEncode(const CString& text)
{
    CStringW wide(text.IsEmpty() ? CString(_T("-")) : text);
    int bytesNeeded = WideCharToMultiByte(CP_UTF8, 0,
                                          wide, wide.GetLength(),
                                          NULL, 0, NULL, NULL);
    if (bytesNeeded <= 0) return "2d";

    std::vector<BYTE> bytes((size_t)bytesNeeded);
    WideCharToMultiByte(CP_UTF8, 0,
                        wide, wide.GetLength(),
                        (LPSTR)bytes.data(), bytesNeeded, NULL, NULL);

    static const char kHex[] = "0123456789ABCDEF";
    CStringA out;
    char* dst = out.GetBuffer(bytesNeeded * 2);
    for (int i = 0; i < bytesNeeded; ++i) {
        dst[i * 2] = kHex[(bytes[i] >> 4) & 0xF];
        dst[i * 2 + 1] = kHex[bytes[i] & 0xF];
    }
    out.ReleaseBuffer(bytesNeeded * 2);
    return out;
}

static void AgentQueryCommandLinesWmi(std::unordered_map<DWORD, CString>& commandLines)
{
    HRESULT hrCo = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    bool needUninit = SUCCEEDED(hrCo);
    if (FAILED(hrCo) && hrCo != RPC_E_CHANGED_MODE) {
        AgentLog(_T("WMI CoInitializeEx failed 0x%08X"), hrCo);
        return;
    }

    HRESULT hrSec = CoInitializeSecurity(NULL, -1, NULL, NULL,
                                         RPC_C_AUTHN_LEVEL_DEFAULT,
                                         RPC_C_IMP_LEVEL_IMPERSONATE,
                                         NULL, EOAC_NONE, NULL);
    if (FAILED(hrSec) && hrSec != RPC_E_TOO_LATE) {
        AgentLog(_T("WMI CoInitializeSecurity failed 0x%08X"), hrSec);
    }

    IWbemLocator* locator = NULL;
    HRESULT hr = CoCreateInstance(CLSID_WbemLocator, NULL, CLSCTX_INPROC_SERVER,
                                  IID_IWbemLocator, (LPVOID*)&locator);
    if (FAILED(hr)) {
        AgentLog(_T("WMI CoCreateInstance failed 0x%08X"), hr);
        if (needUninit) CoUninitialize();
        return;
    }

    IWbemServices* services = NULL;
    BSTR ns = SysAllocString(L"ROOT\\CIMV2");
    hr = locator->ConnectServer(ns, NULL, NULL, NULL, 0, NULL, NULL, &services);
    SysFreeString(ns);
    locator->Release();
    if (FAILED(hr)) {
        AgentLog(_T("WMI ConnectServer failed 0x%08X"), hr);
        if (needUninit) CoUninitialize();
        return;
    }

    CoSetProxyBlanket(services,
                      RPC_C_AUTHN_WINNT,
                      RPC_C_AUTHZ_NONE,
                      NULL,
                      RPC_C_AUTHN_LEVEL_CALL,
                      RPC_C_IMP_LEVEL_IMPERSONATE,
                      NULL,
                      EOAC_NONE);

    IEnumWbemClassObject* enumerator = NULL;
    BSTR wql = SysAllocString(L"WQL");
    BSTR query = SysAllocString(L"SELECT ProcessId, CommandLine FROM Win32_Process");
    hr = services->ExecQuery(wql, query,
                             WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                             NULL, &enumerator);
    SysFreeString(query);
    SysFreeString(wql);
    services->Release();
    if (FAILED(hr)) {
        AgentLog(_T("WMI ExecQuery failed 0x%08X"), hr);
        if (needUninit) CoUninitialize();
        return;
    }

    for (;;) {
        IWbemClassObject* object = NULL;
        ULONG returned = 0;
        hr = enumerator->Next(5000, 1, &object, &returned);
        if (FAILED(hr) || returned == 0) break;

        VARIANT vPid;
        VARIANT vCommand;
        VariantInit(&vPid);
        VariantInit(&vCommand);
        if (SUCCEEDED(object->Get(L"ProcessId", 0, &vPid, NULL, NULL)) &&
            SUCCEEDED(object->Get(L"CommandLine", 0, &vCommand, NULL, NULL)))
        {
            DWORD pid = 0;
            if (vPid.vt == VT_I4 || vPid.vt == VT_UI4) {
                pid = (DWORD)vPid.ulVal;
            }
            if (pid != 0 && vCommand.vt == VT_BSTR && vCommand.bstrVal) {
                commandLines[pid] = CString(vCommand.bstrVal);
            }
        }
        VariantClear(&vCommand);
        VariantClear(&vPid);
        object->Release();
    }

    enumerator->Release();
    AgentLog(_T("WMI command lines loaded: %Iu"), commandLines.size());
    if (needUninit) CoUninitialize();
}

static bool AgentSendReady(SOCKET sock)
{
    sockaddr_in peer = AgentAppPeer();
    CStringA line;
    line.Format("S|agent-ready|pid=%u|build=%s %s\n",
                GetCurrentProcessId(), __DATE__, __TIME__);
    bool ok = AgentSendPacket(sock, peer, line, line.GetLength());
    AgentLog(_T("agent ready response sent ok=%d"), ok ? 1 : 0);
    return ok;
}

static bool AgentSendProcessLine(SOCKET sock,
                                 const sockaddr_in& peer,
                                 DWORD pid,
                                 const CString& user,
                                 const CString& commandLine)
{
    CStringA userHex = Utf8HexEncode(user);
    CStringA commandHex = Utf8HexEncode(commandLine);
    CStringA line;
    line.Format("U|%u|", pid);
    line += userHex;
    line += "|";
    line += commandHex;
    line += "\n";
    return AgentSendPacket(sock, peer, line, line.GetLength());
}

static bool AgentSendProcessEnrich(SOCKET sock)
{
    sockaddr_in peer = AgentAppPeer();
    AgentSendPacket(sock, peer, "S|process-enrich-started\n", 25);

    std::unordered_map<DWORD, CString> commandLines;
    AgentQueryCommandLinesWmi(commandLines);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        AgentLog(_T("CreateToolhelp32Snapshot failed err=%u"), GetLastError());
        return false;
    }

    PROCESSENTRY32W pe = { 0 };
    pe.dwSize = sizeof(pe);
    DWORD sent = 0;
    if (Process32FirstW(snapshot, &pe)) {
        do {
            DWORD pid = pe.th32ProcessID;
            CString user = ArkGetProcessUserName(pid);
            CString commandLine = _T("-");
            auto it = commandLines.find(pid);
            if (it != commandLines.end() && !it->second.IsEmpty()) {
                commandLine = it->second;
            } else {
                commandLine = ArkGetProcessCommandLine(pid);
            }

            if (AgentSendProcessLine(sock, peer, pid, user, commandLine)) {
                ++sent;
            }
            if ((sent % 32) == 31) Sleep(1);
        } while (Process32NextW(snapshot, &pe));
    }
    CloseHandle(snapshot);

    CStringA done;
    done.Format("S|process-enrich-complete|%u\n", sent);
    AgentSendPacket(sock, peer, done, done.GetLength());
    AgentLog(_T("sent process enrichment rows=%u"), sent);
    return true;
}

static int RunScreenAgent()
{
    SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) {
        AgentLog(_T("socket failed err=%u"), WSAGetLastError());
        return 1;
    }

    sockaddr_in local = { 0 };
    local.sin_family = AF_INET;
    local.sin_port = htons(NETDRV_SCREEN_AGENT_PORT);
    local.sin_addr.s_addr = INADDR_ANY;
    if (bind(sock, (sockaddr*)&local, sizeof(local)) == SOCKET_ERROR) {
        AgentLog(_T("bind 0.0.0.0:%u failed err=%u"), NETDRV_SCREEN_AGENT_PORT, WSAGetLastError());
        closesocket(sock);
        return 1;
    }

    AgentLog(_T("listening 0.0.0.0:%u, app=%S:%u"),
             NETDRV_SCREEN_AGENT_PORT, NETDRV_APP_IP_A, NETDRV_UDP_PORT);
    AgentSendReady(sock);
    HANDLE captureThread = CreateThread(NULL, 0, AgentCaptureThreadProc, (LPVOID)(UINT_PTR)sock, 0, NULL);
    if (captureThread) {
        CloseHandle(captureThread);
        AgentLog(_T("screen capture thread started"));
    } else {
        AgentLog(_T("screen capture thread create failed err=%u"), GetLastError());
    }

    for (;;) {
        char buf[256];
        sockaddr_in from = { 0 };
        int fromLen = sizeof(from);
        int n = recvfrom(sock, buf, sizeof(buf), 0, (sockaddr*)&from, &fromLen);
        if (n <= NETDRV_UDP_PACKET_MAGIC_LEN) {
            AgentLog(_T("agent datagram ignored: len=%d"), n);
            continue;
        }
        if (memcmp(buf, NETDRV_UDP_PACKET_MAGIC, NETDRV_UDP_PACKET_MAGIC_LEN) != 0) {
            AgentLog(_T("agent datagram ignored: invalid magic len=%d"), n);
            continue;
        }

        const char* payload = buf + NETDRV_UDP_PACKET_MAGIC_LEN;
        int payloadLen = n - NETDRV_UDP_PACKET_MAGIC_LEN;
        CStringA command(payload, payloadLen);
        AgentLog(_T("agent command datagram payloadLen=%d command=%S"), payloadLen, (LPCSTR)command);
        if (payloadLen == (int)strlen(NETDRV_AGENT_CMD_PING) &&
            memcmp(payload, NETDRV_AGENT_CMD_PING, payloadLen) == 0)
        {
            AgentSendReady(sock);
        } else if (payloadLen == (int)strlen(NETDRV_AGENT_CMD_PROCESS) &&
                   memcmp(payload, NETDRV_AGENT_CMD_PROCESS, payloadLen) == 0)
        {
            AgentLog(_T("process enrichment command received"));
            AgentSendProcessEnrich(sock);
        }
    }
}

static DWORD WINAPI ScreenAgentThreadProc(LPVOID)
{
    RunScreenAgent();
    return 0;
}

static void StartEmbeddedScreenAgent()
{
    HANDLE thread = CreateThread(NULL, 0, ScreenAgentThreadProc, NULL, 0, NULL);
    if (!thread) {
        AgentLog(_T("embedded agent thread create failed err=%u"), GetLastError());
        return;
    }
    CloseHandle(thread);
    AgentLog(_T("embedded agent thread started"));
}

BOOL CArkApp::InitInstance()
{
    INITCOMMONCONTROLSEX icc = { sizeof(icc), ICC_LISTVIEW_CLASSES | ICC_WIN95_CLASSES };
    InitCommonControlsEx(&icc);

    CWinApp::InitInstance();
    if (!AfxSocketInit()) { AfxMessageBox(_T("AfxSocketInit failed")); return FALSE; }

    CString cmd(m_lpCmdLine);
    cmd.MakeLower();
    if (cmd.Find(_T("/agent")) >= 0 || cmd.Find(_T("-agent")) >= 0) {
        RunScreenAgent();
        return FALSE;
    }

    if (cmd.Find(_T("/withagent")) >= 0 || cmd.Find(_T("-withagent")) >= 0) {
        StartEmbeddedScreenAgent();
    }

    CArkDlg dlg;
    m_pMainWnd = &dlg;
    dlg.DoModal();
    return FALSE;
}
