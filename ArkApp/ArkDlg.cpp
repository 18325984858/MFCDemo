#include "stdafx.h"
#include "ArkDlg.h"
#include "ProcEnrich.h"
#include "resource.h"
#include "../NetDrv/Ioctl.h"

#include <cstdarg>

static std::vector<CStringA> SplitA(const CStringA& text, char delimiter)
{
    std::vector<CStringA> fields;
    int start = 0;
    for (int i = 0; i <= text.GetLength(); ++i) {
        if (i == text.GetLength() || text[i] == delimiter) {
            fields.push_back(text.Mid(start, i - start));
            start = i + 1;
        }
    }
    return fields;
}

CArkDlg::CArkDlg(CWnd* pParent) : CDialogEx(IDD, pParent) {}

void CArkDlg::Log(LPCTSTR format, ...)
{
    CString message;
    va_list args;
    va_start(args, format);
    message.FormatV(format, args);
    va_end(args);

    SYSTEMTIME st;
    GetLocalTime(&st);

    CString line;
    line.Format(_T("%04u-%02u-%02u %02u:%02u:%02u.%03u %s\r\n"),
                st.wYear, st.wMonth, st.wDay,
                st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
                (LPCTSTR)message);

    CString debugLine = _T("[ArkApp] ") + line;
    OutputDebugString(debugLine);

    if (m_logPath.IsEmpty()) {
        TCHAR exePath[MAX_PATH] = { 0 };
        GetModuleFileName(NULL, exePath, MAX_PATH);
        m_logPath = exePath;
        int slash = m_logPath.ReverseFind(_T('\\'));
        if (slash >= 0) {
            m_logPath = m_logPath.Left(slash + 1);
        } else {
            m_logPath.Empty();
        }
        m_logPath += _T("arkapp.log");
    }

    HANDLE file = CreateFile(m_logPath, FILE_APPEND_DATA,
                             FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                             OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        return;
    }

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
}

void CArkDlg::DoDataExchange(CDataExchange* pDX)
{
    CDialogEx::DoDataExchange(pDX);
    DDX_Control(pDX, IDC_TAB,          m_tab);
    DDX_Control(pDX, IDC_LIST_PROCESS, m_listProc);
    DDX_Control(pDX, IDC_LIST_DRIVER,  m_listDrv);
    DDX_Control(pDX, IDC_FILE_TREE,    m_fileTree);
    DDX_Control(pDX, IDC_FILE_LIST,    m_fileList);
    DDX_Control(pDX, IDC_SHOT_VIEW,    m_shotView);
    DDX_Control(pDX, IDC_STATUS_TEXT,  m_status);
}

BEGIN_MESSAGE_MAP(CArkDlg, CDialogEx)
    ON_BN_CLICKED(IDC_BTN_REFRESH,  &CArkDlg::OnBnClickedRefresh)
    ON_BN_CLICKED(IDC_BTN_DOWNLOAD, &CArkDlg::OnBnClickedDownload)
    ON_BN_CLICKED(IDC_BTN_UPLOAD,   &CArkDlg::OnBnClickedUpload)
    ON_BN_CLICKED(IDC_BTN_LANG,     &CArkDlg::OnBnClickedLang)
    ON_NOTIFY(TCN_SELCHANGE, IDC_TAB, &CArkDlg::OnTabSelChange)
    ON_NOTIFY(TVN_ITEMEXPANDING, IDC_FILE_TREE, &CArkDlg::OnTreeItemExpanding)
    ON_NOTIFY(TVN_SELCHANGED,    IDC_FILE_TREE, &CArkDlg::OnTreeSelChanged)
    ON_WM_SIZE()
    ON_WM_GETMINMAXINFO()
    ON_WM_TIMER()
    ON_WM_DESTROY()
END_MESSAGE_MAP()

BOOL CArkDlg::OnInitDialog()
{
    CDialogEx::OnInitDialog();
    CString title;
    title.Format(_T("NetDrv ARK  build %hs %hs"), __DATE__, __TIME__);
    SetWindowText(title);

    BuildDriveLetterMap();

    // Tabs
    m_tab.InsertItem(0, _T("进程"));
    m_tab.InsertItem(1, _T("驱动模块"));
    m_tab.InsertItem(2, _T("文件"));
    m_tab.InsertItem(3, _T("截图"));
    m_tab.SetCurSel(0);

    // Two list-view tables.
    m_listProc.SetExtendedStyle(LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
    int c = 0;
    m_listProc.InsertColumn(c++, _T("映像名称"), LVCFMT_LEFT,  140);
    m_listProc.InsertColumn(c++, _T("进程ID"),  LVCFMT_RIGHT,  60);
    m_listProc.InsertColumn(c++, _T("父进程ID"), LVCFMT_RIGHT,  60);
    m_listProc.InsertColumn(c++, _T("会话ID"),  LVCFMT_RIGHT,  50);
    m_listProc.InsertColumn(c++, _T("用户名"),  LVCFMT_LEFT,  130);
    m_listProc.InsertColumn(c++, _T("映像路径"), LVCFMT_LEFT,  260);
    m_listProc.InsertColumn(c++, _T("EPROCESS"), LVCFMT_LEFT, 130);
    m_listProc.InsertColumn(c++, _T("签名"),    LVCFMT_LEFT,   60);
    m_listProc.InsertColumn(c++, _T("文件厂商"), LVCFMT_LEFT,  150);
    m_listProc.InsertColumn(c++, _T("创建时间"), LVCFMT_LEFT,  140);
    m_listProc.InsertColumn(c++, _T("启动参数"), LVCFMT_LEFT,  300);

    m_listDrv.SetExtendedStyle(LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
    int dc = 0;
    m_listDrv.InsertColumn(dc++, _T("驱动名"),    LVCFMT_LEFT,  140);
    m_listDrv.InsertColumn(dc++, _T("基地址"),    LVCFMT_LEFT,  120);
    m_listDrv.InsertColumn(dc++, _T("大小"),      LVCFMT_RIGHT,  90);
    m_listDrv.InsertColumn(dc++, _T("加载顺序"),  LVCFMT_RIGHT,  60);
    m_listDrv.InsertColumn(dc++, _T("驱动对象"),  LVCFMT_LEFT,  120);
    m_listDrv.InsertColumn(dc++, _T("对象名称"),  LVCFMT_LEFT,  150);
    m_listDrv.InsertColumn(dc++, _T("服务名称"),  LVCFMT_LEFT,  120);
    m_listDrv.InsertColumn(dc++, _T("数字签名"),  LVCFMT_LEFT,   70);
    m_listDrv.InsertColumn(dc++, _T("公司名"),    LVCFMT_LEFT,  150);
    m_listDrv.InsertColumn(dc++, _T("路径"),      LVCFMT_LEFT,  340);

    // File list columns (name / size / type).
    m_fileList.SetExtendedStyle(LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
    m_fileList.InsertColumn(0, _T("名称"),    LVCFMT_LEFT,  360);
    m_fileList.InsertColumn(1, _T("大小"),    LVCFMT_RIGHT, 140);
    m_fileList.InsertColumn(2, _T("类型"),    LVCFMT_LEFT,   80);
    InitFileTab();

    CString s;
    s.Format(_T("Network driver %s:%u | build %hs %hs"),
             NETDRV_DRIVER_IP_W, NETDRV_UDP_PORT, __DATE__, __TIME__);
    LPCTSTR udpBindIp = _T("0.0.0.0");
    Log(_T("app start, driver=%s:%u, listen=%s:%u bind=%s:%u"),
        NETDRV_DRIVER_IP_W, NETDRV_UDP_PORT,
        NETDRV_APP_IP_W, NETDRV_UDP_PORT,
        udpBindIp, NETDRV_UDP_PORT);
    Log(_T("app build %hs %hs"), __DATE__, __TIME__);
    ShellExecuteW(NULL, L"open", L"netsh.exe",
                  L"advfirewall firewall add rule name=\"ArkApp UDP 9999 In\" dir=in action=allow protocol=UDP localport=9999",
                  NULL, SW_HIDE);

    // UDP listener.
    m_udp = std::make_unique<CArkUdp>(this);
    if (m_udp->Start(udpBindIp, NETDRV_UDP_PORT)) {
        CString tmp;
        tmp.Format(_T(" | UDP listening %s:%u"), udpBindIp, NETDRV_UDP_PORT);
        s += tmp;
        Log(_T("UDP listener started on %s:%u expected-app-ip=%s"),
            udpBindIp, NETDRV_UDP_PORT, NETDRV_APP_IP_W);
    } else {
        s += _T(" | UDP bind FAILED");
        Log(_T("UDP listener bind FAILED on %s:%u, err=%u"),
            udpBindIp, NETDRV_UDP_PORT, WSAGetLastError());
    }
    m_status.SetWindowText(s);
    return TRUE;
}

void CArkDlg::OnDestroy()
{
    Log(_T("app destroy, txCommands=%u rxLines=%u"), m_txCommands, m_rxLines);
    ClearShotBitmap();
    if (m_dlFile != INVALID_HANDLE_VALUE) {
        CloseHandle(m_dlFile);
        m_dlFile = INVALID_HANDLE_VALUE;
    }
    if (m_udp) { m_udp->Close(); m_udp.reset(); }
    CDialogEx::OnDestroy();
}

void CArkDlg::SendDriverCommand(LPCSTR command, LPCTSTR label)
{
    if (m_udp && command && m_udp->SendCommand(command)) {
        ++m_txCommands;
        CString s;
        s.Format(_T("[%s] UDP command sent to %s:%u"),
                 label, NETDRV_DRIVER_IP_W, NETDRV_UDP_PORT);
        m_status.SetWindowText(s);
        Log(_T("TX command #%u label=%s payload=%S target=%s:%u"),
            m_txCommands, label, command, NETDRV_DRIVER_IP_W, NETDRV_UDP_PORT);
        return;
    }

    CString s;
    s.Format(_T("[%s] UDP command send failed: %u"), label, WSAGetLastError());
    m_status.SetWindowText(s);
    Log(_T("TX command FAILED label=%s payload=%S err=%u"),
        label, command ? command : "(null)", WSAGetLastError());
}

void CArkDlg::OnBnClickedLang()
{
    m_isEnglish = !m_isEnglish;
    ApplyLanguage();
}

static void SetColumnText(CListCtrl& lc, int col, LPCTSTR text)
{
    LVCOLUMN lvc = {};
    lvc.mask = LVCF_TEXT;
    lvc.pszText = (LPTSTR)text;
    lc.SetColumn(col, &lvc);
}

void CArkDlg::ApplyLanguage()
{
    bool en = m_isEnglish;
    GetDlgItem(IDC_BTN_LANG)->SetWindowText(en ? _T("CN") : _T("EN"));
    GetDlgItem(IDC_BTN_DOWNLOAD)->SetWindowText(en ? _T("Download") : _T("\x4E0B\x8F7D"));
    GetDlgItem(IDC_BTN_UPLOAD)->SetWindowText(en ? _T("Upload") : _T("\x4E0A\x4F20"));

    /* Tabs */
    TCITEM ti = {}; ti.mask = TCIF_TEXT;
    LPCTSTR tabs_cn[] = { _T("\x8FDB\x7A0B"), _T("\x9A71\x52A8\x6A21\x5757"), _T("\x6587\x4EF6"), _T("\x622A\x56FE") };
    LPCTSTR tabs_en[] = { _T("Process"), _T("Driver"), _T("File"), _T("Screenshot") };
    for (int i = 0; i < 4; i++) {
        ti.pszText = (LPTSTR)(en ? tabs_en[i] : tabs_cn[i]);
        m_tab.SetItem(i, &ti);
    }

    /* Process list columns */
    LPCTSTR pc_cn[] = { _T("\x6620\x50CF\x540D\x79F0"), _T("\x8FDB\x7A0BID"), _T("\x7236\x8FDB\x7A0BID"),
        _T("\x4F1A\x8BDDID"), _T("\x7528\x6237\x540D"), _T("\x6620\x50CF\x8DEF\x5F84"),
        _T("EPROCESS"), _T("\x7B7E\x540D"), _T("\x6587\x4EF6\x5382\x5546"),
        _T("\x521B\x5EFA\x65F6\x95F4"), _T("\x542F\x52A8\x53C2\x6570") };
    LPCTSTR pc_en[] = { _T("Image"), _T("PID"), _T("PPID"), _T("Session"),
        _T("User"), _T("Path"), _T("EPROCESS"), _T("Sign"),
        _T("Vendor"), _T("Created"), _T("CmdLine") };
    for (int i = 0; i < 11; i++)
        SetColumnText(m_listProc, i, en ? pc_en[i] : pc_cn[i]);

    /* Driver list columns */
    LPCTSTR dc_cn[] = { _T("\x9A71\x52A8\x540D"), _T("\x57FA\x5730\x5740"), _T("\x5927\x5C0F"),
        _T("\x52A0\x8F7D\x987A\x5E8F"), _T("\x9A71\x52A8\x5BF9\x8C61"), _T("\x5BF9\x8C61\x540D\x79F0"),
        _T("\x670D\x52A1\x540D\x79F0"), _T("\x6570\x5B57\x7B7E\x540D"), _T("\x516C\x53F8\x540D"),
        _T("\x8DEF\x5F84") };
    LPCTSTR dc_en[] = { _T("Driver"), _T("Base"), _T("Size"), _T("Order"),
        _T("DrvObj"), _T("ObjName"), _T("Service"), _T("Sign"),
        _T("Company"), _T("Path") };
    for (int i = 0; i < 10; i++)
        SetColumnText(m_listDrv, i, en ? dc_en[i] : dc_cn[i]);

    /* File list columns */
    LPCTSTR fc_cn[] = { _T("\x540D\x79F0"), _T("\x5927\x5C0F"), _T("\x7C7B\x578B") };
    LPCTSTR fc_en[] = { _T("Name"), _T("Size"), _T("Type") };
    for (int i = 0; i < 3; i++)
        SetColumnText(m_fileList, i, en ? fc_en[i] : fc_cn[i]);

    m_tab.Invalidate();
    m_listProc.Invalidate();
    m_listDrv.Invalidate();
    m_fileList.Invalidate();

    /* Re-layout buttons (English labels are wider) */
    CRect rc;
    GetClientRect(&rc);
    SendMessage(WM_SIZE, SIZE_RESTORED, MAKELPARAM(rc.Width(), rc.Height()));
}

void CArkDlg::OnBnClickedRefresh()
{
    if (CurrentTab() == 0) {
        m_listProc.DeleteAllItems();
        m_inProcBatch = false;
        m_processRows.clear();
        SendDriverCommand(NETDRV_CMD_ENUM_PROCESS, _T("process"));
    } else if (CurrentTab() == 1) {
        m_listDrv.DeleteAllItems();
        m_inDrvBatch = false;
        SendDriverCommand(NETDRV_CMD_ENUM_DRIVER, _T("driver"));
    } else if (CurrentTab() == 2) {
        // Re-enumerate the currently selected tree directory; if none, re-init drives.
        HTREEITEM sel = m_fileTree.GetSelectedItem();
        if (sel) {
            CString path = GetTreeItemPath(sel);
            m_fileLoaded.erase(sel);
            m_fileEntries.erase(sel);
            while (HTREEITEM c = m_fileTree.GetChildItem(sel)) m_fileTree.DeleteItem(c);
            RequestFileEnum(path);
        } else {
            m_fileTree.DeleteAllItems();
            m_fileTreeIndex.clear();
            m_fileEntries.clear();
            m_fileLoaded.clear();
            InitFileTab();
        }
    } else if (CurrentTab() == 3) {
        m_shotReceiving = false;
        m_shotReceived = 0;
        m_shotExpected = 0;
        m_shotImage.clear();
        m_shotChunkSeen.clear();
        ClearShotBitmap();
        m_shotLive = true;
        SendDriverCommand(NETDRV_CMD_SCREENSHOT, _T("screenshot"));
    }
}

int CArkDlg::CurrentTab() const
{
    return const_cast<CTabCtrl&>(m_tab).GetCurSel();
}

void CArkDlg::BuildDriveLetterMap()
{
    m_driveMap.clear();
    WCHAR drives[256] = { 0 };
    DWORD n = GetLogicalDriveStringsW(_countof(drives), drives);
    if (n == 0) return;
    for (LPWSTR d = drives; *d; d += wcslen(d) + 1) {
        WCHAR letter[3] = { d[0], L':', 0 };
        WCHAR target[MAX_PATH] = { 0 };
        if (QueryDosDeviceW(letter, target, _countof(target))) {
            m_driveMap.emplace_back(CString(letter), CString(target));
        }
    }
}

CString CArkDlg::NtPathToDos(const CString& nt) const
{
    if (nt.IsEmpty() || nt == _T("-")) return nt;

    // \SystemRoot\xxx -> C:\Windows\xxx
    if (_tcsnicmp(nt, _T("\\SystemRoot\\"), 12) == 0) {
        TCHAR winDir[MAX_PATH]; GetWindowsDirectory(winDir, MAX_PATH);
        return CString(winDir) + _T("\\") + nt.Mid(12);
    }
    // \??\C:\xxx -> C:\xxx
    if (_tcsnicmp(nt, _T("\\??\\"), 4) == 0) {
        return nt.Mid(4);
    }
    // \Device\HarddiskVolumeN\xxx -> map by drive letter table.
    for (const auto& kv : m_driveMap) {
        int tlen = kv.second.GetLength();
        if (nt.GetLength() > tlen &&
            _tcsnicmp(nt, kv.second, tlen) == 0 &&
            nt[tlen] == _T('\\'))
        {
            return kv.first + nt.Mid(tlen);
        }
    }
    return nt;
}

void CArkDlg::OnTabSelChange(NMHDR*, LRESULT* pResult)
{
    if (CurrentTab() != 3) {
        m_shotLive = false;
        KillTimer(100);
    }
    UpdateTabVisibility();
    if (pResult) *pResult = 0;
}

void CArkDlg::UpdateTabVisibility()
{
    int sel = m_tab.GetCurSel();
    m_listProc .ShowWindow(sel == 0 ? SW_SHOW : SW_HIDE);
    m_listDrv  .ShowWindow(sel == 1 ? SW_SHOW : SW_HIDE);
    m_fileTree .ShowWindow(sel == 2 ? SW_SHOW : SW_HIDE);
    m_fileList .ShowWindow(sel == 2 ? SW_SHOW : SW_HIDE);
    m_shotView .ShowWindow(sel == 3 ? SW_SHOW : SW_HIDE);
    if (sel == 3 && m_hShotBitmap) RenderShotToView();
}

void CArkDlg::OnSize(UINT nType, int cx, int cy)
{
    CDialogEx::OnSize(nType, cx, cy);
    if (!::IsWindow(m_tab.GetSafeHwnd())) return;
    if (cx <= 0 || cy <= 0) return;

    const int margin   = 6;
    const int statusH  = 18;
    const int btnW     = 70;
    const int btnH     = 22;
    const int tabH     = 22;
    const int dlW      = m_isEnglish ? 76 : 60;
    const int ulW      = m_isEnglish ? 64 : 60;
    const int lnW      = 40;

    // Tab strip
    m_tab.SetWindowPos(NULL,
        margin, margin,
        cx - margin * 2 - btnW - margin - dlW - margin - ulW - margin - lnW - margin, tabH,
        SWP_NOZORDER);

    // Refresh button
    int rx = cx - margin - btnW;
    GetDlgItem(IDC_BTN_REFRESH)->SetWindowPos(NULL,
        rx, margin, btnW, btnH, SWP_NOZORDER);
    // Download
    rx -= margin + dlW;
    GetDlgItem(IDC_BTN_DOWNLOAD)->SetWindowPos(NULL,
        rx, margin, dlW, btnH, SWP_NOZORDER);
    // Upload
    rx -= margin + ulW;
    GetDlgItem(IDC_BTN_UPLOAD)->SetWindowPos(NULL,
        rx, margin, ulW, btnH, SWP_NOZORDER);
    // Language toggle
    rx -= margin + lnW;
    GetDlgItem(IDC_BTN_LANG)->SetWindowPos(NULL,
        rx, margin, lnW, btnH, SWP_NOZORDER);

    // Content area — below tab strip, above status bar.
    int listTop    = margin + tabH + margin;
    int listH      = cy - listTop - statusH - margin;
    int listW      = cx - margin * 2;
    if (listH < 50) listH = 50;

    m_listProc.SetWindowPos(NULL, margin, listTop, listW, listH, SWP_NOZORDER);
    m_listDrv .SetWindowPos(NULL, margin, listTop, listW, listH, SWP_NOZORDER);

    // File tab: tree on the left third, file list on the right.
    int treeW  = max(180, listW / 3);
    int fileLW = listW - treeW - margin;
    m_fileTree.SetWindowPos(NULL, margin, listTop, treeW, listH, SWP_NOZORDER);
    m_fileList.SetWindowPos(NULL, margin + treeW + margin, listTop, fileLW, listH, SWP_NOZORDER);
    m_shotView.SetWindowPos(NULL, margin, listTop, listW, listH, SWP_NOZORDER);
    if (CurrentTab() == 3 && !m_shotImage.empty()) {
        RenderShotToView();
    }

    // Status bar — bottom.
    m_status.SetWindowPos(NULL,
        margin, cy - statusH,
        cx - margin * 2, statusH - 2,
        SWP_NOZORDER);
}

void CArkDlg::OnGetMinMaxInfo(MINMAXINFO* lpMMI)
{
    lpMMI->ptMinTrackSize.x = 700;
    lpMMI->ptMinTrackSize.y = 320;
    CDialogEx::OnGetMinMaxInfo(lpMMI);
}

void CArkDlg::OnTimer(UINT_PTR nIDEvent)
{
    if (nIDEvent == 100) {
        KillTimer(100);
        if (m_shotLive && CurrentTab() == 3 && !m_shotReceiving) {
            SendDriverCommand(NETDRV_CMD_SCREENSHOT, _T("screenshot"));
        }
    }
    CDialogEx::OnTimer(nIDEvent);
}

void CArkDlg::OnArkPacket(const char* payload, int payloadLen)
{
    if (!payload || payloadLen <= 0) return;

    CStringA text(payload, payloadLen);
    int start = 0;
    for (int i = 0; i <= text.GetLength(); ++i) {
        if (i == text.GetLength() || text[i] == '\n') {
            CStringA line = text.Mid(start, i - start);
            line.TrimRight('\r');
            if (!line.IsEmpty()) {
                OnArkLine(line);
            }
            start = i + 1;
        }
    }
}

// ---- line parser ----

static CString AtoW(const CStringA& a)
{
    CString w;
    int n = MultiByteToWideChar(CP_UTF8, 0, a, a.GetLength(), NULL, 0);
    if (n > 0) {
        MultiByteToWideChar(CP_UTF8, 0, a, a.GetLength(),
                            w.GetBuffer(n), n);
        w.ReleaseBuffer(n);
    }
    return w;
}

static int HexValue(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static CString HexUtf8ToW(const CStringA& hex)
{
    if ((hex.GetLength() & 1) != 0) return _T("-");

    std::vector<char> bytes((size_t)hex.GetLength() / 2);
    for (int i = 0; i < hex.GetLength(); i += 2) {
        int hi = HexValue(hex[i]);
        int lo = HexValue(hex[i + 1]);
        if (hi < 0 || lo < 0) return _T("-");
        bytes[(size_t)i / 2] = (char)((hi << 4) | lo);
    }

    if (bytes.empty()) return _T("-");
    int chars = MultiByteToWideChar(CP_UTF8, 0,
                                    bytes.data(), (int)bytes.size(),
                                    NULL, 0);
    if (chars <= 0) return _T("-");

    CString out;
    MultiByteToWideChar(CP_UTF8, 0,
                        bytes.data(), (int)bytes.size(),
                        out.GetBuffer(chars), chars);
    out.ReleaseBuffer(chars);
    return out;
}

// FILETIME 100ns since 1601 (LARGE_INTEGER quad) -> "YYYY/MM/DD HH:MM:SS" local.
static CString FormatFileTime100ns(LONGLONG ft)
{
    FILETIME utc;
    utc.dwLowDateTime  = (DWORD)(ft & 0xFFFFFFFF);
    utc.dwHighDateTime = (DWORD)(ft >> 32);
    FILETIME loc; SYSTEMTIME st;
    if (!FileTimeToLocalFileTime(&utc, &loc)) return _T("-");
    if (!FileTimeToSystemTime(&loc, &st))     return _T("-");
    CString s;
    s.Format(_T("%04u/%02u/%02u %02u:%02u:%02u"),
             st.wYear, st.wMonth, st.wDay,
             st.wHour, st.wMinute, st.wSecond);
    return s;
}

void CArkDlg::ApplyProcessExtra(const CStringA& rest)
{
    std::vector<CStringA> f = SplitA(rest, '|');
    if (f.size() < 3) {
        Log(_T("process extra ignored: %S"), (LPCSTR)rest);
        return;
    }

    DWORD pid = (DWORD)_atoi64(f[0]);
    auto it = m_processRows.find(pid);
    if (it == m_processRows.end()) {
        return;
    }

    int row = it->second;
    CString user = HexUtf8ToW(f[1]);
    CString commandLine = HexUtf8ToW(f[2]);
    if (!user.IsEmpty() && user != _T("-")) {
        m_listProc.SetItemText(row, 4, user);
    }
    if (!commandLine.IsEmpty() && commandLine != _T("-")) {
        m_listProc.SetItemText(row, 10, commandLine);
    }
}

void CArkDlg::OnArkLine(const CStringA& line)
{
    ++m_rxLines;

    if (line.GetLength() < 2 || line[1] != '|') {
        Log(_T("RX line #%u ignored: malformed '%S'"), m_rxLines, (LPCSTR)line);
        return;
    }

    char tag = line[0];
    CStringA rest = line.Mid(2);
    if (tag != 'Y' && tag != 'G') {
        if (line.GetLength() > 220) {
            Log(_T("RX line #%u tag=%c len=%d"), m_rxLines, tag, line.GetLength());
        } else {
            Log(_T("RX line #%u tag=%c text=%S"), m_rxLines, tag, (LPCSTR)line);
        }
    }

    if (tag == 'B') {
        if (rest == "process") {
            m_inProcBatch = true;
            m_status.SetWindowText(_T("[process] receiving batch"));
        }
        else if (rest == "driver") {
            m_inDrvBatch = true;
            m_status.SetWindowText(_T("[driver] receiving batch"));
        }
        else if (rest.Left(5) == "file|") {
            CString path = HexUtf8ToW(rest.Mid(5));
            BeginFileBatch(path);
        }
        else if (rest.Left(5) == "shot|") {
            BeginShotFrame(rest.Mid(5));
        }
        else if (rest.Left(4) == "get|") {
            // B|get|<pathHex>|<totalHex>|<chunkSize>|<chunkCount>
            CStringA tail = rest.Mid(4);
            int p1 = tail.Find('|');
            if (p1 > 0) {
                CString remote = HexUtf8ToW(tail.Left(p1));
                CStringA after = tail.Mid(p1 + 1);
                int p2 = after.Find('|');
                CStringA totalHex = (p2 > 0) ? after.Left(p2) : after;
                ULONGLONG total = (ULONGLONG)_strtoui64(totalHex, NULL, 16);
                BeginDownload(remote, m_dlLocalPath, total);
            }
        }
        return;
    }
    if (tag == 'E') {
        m_inProcBatch = false;
        m_inDrvBatch  = false;
        if (rest.Left(5) == "file|") {
            int sep = rest.Find('|', 5);
            CStringA hex = (sep > 0) ? rest.Mid(5, sep - 5) : rest.Mid(5);
            CString path = HexUtf8ToW(hex);
            EndFileBatch(path);
            return;
        }
        if (rest.Left(4) == "get|") {
            int p1 = rest.Find('|', 4);
            ULONGLONG sent = 0;
            if (p1 > 0) sent = (ULONGLONG)_strtoui64((LPCSTR)rest.Mid(p1 + 1), NULL, 10);
            EndDownload(sent);
            return;
        }
        if (rest.Left(5) == "shot|") {
            EndShotFrame(rest.Mid(5));
            return;
        }
        CString s;
        s.Format(_T("[%S] batch end: %S"), (LPCSTR)rest, (LPCSTR)line);
        m_status.SetWindowText(s);
        Log(_T("%s"), (LPCTSTR)s);
        return;
    }

    if (tag == 'Y') {
        AppendShotChunk(rest);
        return;
    }

    if (tag == 'G') {
        // G|<idx>|<offHex>|<lenHex>|<dataHex>
        std::vector<CStringA> f;
        int start = 0;
        for (int i = 0; i <= rest.GetLength(); ++i) {
            if (i == rest.GetLength() || rest[i] == '|') {
                f.push_back(rest.Mid(start, i - start));
                start = i + 1;
                if (f.size() == 3) {
                    // last field is the hex blob; take remainder verbatim
                    f.push_back(rest.Mid(i + 1));
                    break;
                }
            }
        }
        if (f.size() < 4) return;
        ULONGLONG off = (ULONGLONG)_strtoui64(f[1], NULL, 16);
        ULONG     len = (ULONG)_strtoui64(f[2], NULL, 16);
        const CStringA& hex = f[3];
        if ((int)(len * 2) > hex.GetLength()) return;
        std::vector<BYTE> bin(len);
        for (ULONG k = 0; k < len; ++k) {
            int hi = (hex[k * 2]     >= 'a') ? hex[k * 2]     - 'a' + 10 :
                     (hex[k * 2]     >= 'A') ? hex[k * 2]     - 'A' + 10 : hex[k * 2]     - '0';
            int lo = (hex[k * 2 + 1] >= 'a') ? hex[k * 2 + 1] - 'a' + 10 :
                     (hex[k * 2 + 1] >= 'A') ? hex[k * 2 + 1] - 'A' + 10 : hex[k * 2 + 1] - '0';
            bin[k] = (BYTE)((hi << 4) | lo);
        }
        AppendDownloadChunk(off, bin.data(), len);
        return;
    }

    if (tag == 'F') {
        // F|<isDir>|<sizeHex>|<nameHex>
        std::vector<CStringA> f;
        int start = 0;
        for (int i = 0; i <= rest.GetLength(); ++i) {
            if (i == rest.GetLength() || rest[i] == '|') {
                f.push_back(rest.Mid(start, i - start));
                start = i + 1;
            }
        }
        if (f.size() < 3) return;
        bool      isDir = (f[0] == "1");
        ULONGLONG size  = (ULONGLONG)_strtoui64(f[1], NULL, 16);
        CString   name  = HexUtf8ToW(f[2]);
        AppendFileEntry(isDir, size, name);
        return;
    }

    if (tag == 'S') {
        CString s;
        s.Format(_T("[status] %S"), (LPCSTR)rest);
        m_status.SetWindowText(s);
        Log(_T("%s"), (LPCTSTR)s);
        return;
    }

    if (tag == 'U') {
        ApplyProcessExtra(rest);
        return;
    }

    if (tag == 'P') {
        // P| pid | ppid | sess | eproc | createTime | name | path
        CStringA f[7];
        int idx = 0, start = 0;
        for (int i = 0; i <= rest.GetLength() && idx < 7; ++i) {
            if (i == rest.GetLength() || rest[i] == '|') {
                f[idx++] = (idx == 6)
                    ? rest.Mid(start)                 // last = full remainder (path)
                    : rest.Mid(start, i - start);
                start = i + 1;
            }
        }

        DWORD pid     = (DWORD)_atoi64(f[0]);
        CString name  = AtoW(f[5]);
        CString path  = AtoW(f[6]);
        path.TrimRight();
        CString dosPath = NtPathToDos(path);
        CString ctime = FormatFileTime100ns(_atoi64(f[4]));

        ArkEnrich en;
        ArkEnrichProcess(pid, dosPath, en);

        int row = m_listProc.InsertItem(m_listProc.GetItemCount(), name);
        m_listProc.SetItemText(row, 1, AtoW(f[0]));
        m_listProc.SetItemText(row, 2, AtoW(f[1]));
        m_listProc.SetItemText(row, 3, AtoW(f[2]));
        m_listProc.SetItemText(row, 4, en.UserName);
        m_listProc.SetItemText(row, 5, path);
        m_listProc.SetItemText(row, 6, AtoW(f[3]));
        m_listProc.SetItemText(row, 7, en.SignStatus);
        m_listProc.SetItemText(row, 8, en.FileVendor);
        m_listProc.SetItemText(row, 9, ctime);
        m_listProc.SetItemText(row, 10, en.CommandLine);
        m_processRows[pid] = row;
        if ((row + 1) == 1 || ((row + 1) % 50) == 0) {
            CString s;
            s.Format(_T("[process] displayed %d rows"), row + 1);
            m_status.SetWindowText(s);
            Log(_T("%s"), (LPCTSTR)s);
        }
        return;
    }

    if (tag == 'D') {
        // D| name | base | size | loadOrder | drvObj | objName | svcName | path
        CStringA f[8];
        int idx = 0, start = 0;
        for (int i = 0; i <= rest.GetLength() && idx < 8; ++i) {
            if (i == rest.GetLength() || rest[i] == '|') {
                f[idx++] = (idx == 7)
                    ? rest.Mid(start)
                    : rest.Mid(start, i - start);
                start = i + 1;
            }
        }

        CString name = AtoW(f[0]);
        CString path = AtoW(f[7]);
        // Translate to a real DOS path for version/sign check.
        CString dosPath = NtPathToDos(path);

        CString vendor = _T("-");
        CString sign   = _T("-");
        {
            ArkEnrich e;
            // Reuse process enricher just for FileVendor/SignStatus path lookups.
            ArkEnrichProcess(0xFFFFFFFF, dosPath, e);
            vendor = e.FileVendor;
            sign   = e.SignStatus;
        }

        int row = m_listDrv.InsertItem(m_listDrv.GetItemCount(), name);
        m_listDrv.SetItemText(row, 1, AtoW(f[1]));
        m_listDrv.SetItemText(row, 2, AtoW(f[2]));
        m_listDrv.SetItemText(row, 3, AtoW(f[3]));
        m_listDrv.SetItemText(row, 4, AtoW(f[4]));
        m_listDrv.SetItemText(row, 5, AtoW(f[5]));
        m_listDrv.SetItemText(row, 6, AtoW(f[6]));
        m_listDrv.SetItemText(row, 7, sign);
        m_listDrv.SetItemText(row, 8, vendor);
        m_listDrv.SetItemText(row, 9, path);
        if ((row + 1) == 1 || ((row + 1) % 50) == 0) {
            CString s;
            s.Format(_T("[driver] displayed %d rows"), row + 1);
            m_status.SetWindowText(s);
            Log(_T("%s"), (LPCTSTR)s);
        }
    }
}

// ---- file tab implementation ----

static CStringA WToUtf8(const CString& w)
{
    CStringW ws(w);
    int n = WideCharToMultiByte(CP_UTF8, 0, ws, ws.GetLength(), NULL, 0, NULL, NULL);
    if (n <= 0) return CStringA();
    CStringA out;
    char* dst = out.GetBuffer(n);
    WideCharToMultiByte(CP_UTF8, 0, ws, ws.GetLength(), dst, n, NULL, NULL);
    out.ReleaseBuffer(n);
    return out;
}

CString CArkDlg::JoinPath(const CString& parent, const CString& name)
{
    if (parent.IsEmpty()) return name;
    if (parent.GetAt(parent.GetLength() - 1) == _T('\\')) return parent + name;
    return parent + _T("\\") + name;
}

CString CArkDlg::GetTreeItemPath(HTREEITEM item) const
{
    if (!item) return CString();
    CTreeCtrl& tree = const_cast<CTreeCtrl&>(m_fileTree);
    CString name = tree.GetItemText(item);
    HTREEITEM parent = tree.GetParentItem(item);
    if (!parent) return name;            // drive root, e.g. "C:\"
    return JoinPath(GetTreeItemPath(parent), name);
}

void CArkDlg::InitFileTab()
{
    WCHAR drives[256] = { 0 };
    DWORD n = GetLogicalDriveStringsW(_countof(drives), drives);
    if (n == 0) return;

    HTREEITEM after = TVI_LAST;
    for (LPWSTR d = drives; *d; d += wcslen(d) + 1) {
        CString driveText(d);                 // "C:\"
        HTREEITEM h = m_fileTree.InsertItem(driveText, TVI_ROOT, after);
        after = h;
        // dummy child so expand arrow shows.
        m_fileTree.InsertItem(_T("..."), h, TVI_LAST);
        m_fileTreeIndex[std::wstring((LPCWSTR)driveText)] = h;
    }
}

void CArkDlg::RequestFileEnum(const CString& path)
{
    CStringA pathUtf8 = WToUtf8(path);
    CStringA cmd;
    cmd.Format("%s%s\n", NETDRV_CMD_ENUM_FILE, (LPCSTR)pathUtf8);

    if (m_udp && m_udp->SendCommand(cmd)) {
        ++m_txCommands;
        Log(_T("TX command #%u file path=%s"), m_txCommands, (LPCTSTR)path);
        CString s;
        s.Format(_T("[file] requesting %s"), (LPCTSTR)path);
        m_status.SetWindowText(s);
    } else {
        Log(_T("TX file command FAILED path=%s err=%u"), (LPCTSTR)path, WSAGetLastError());
    }
}

void CArkDlg::BeginFileBatch(const CString& path)
{
    m_filePending = path;
    m_fileIncoming.clear();
    CString s;
    s.Format(_T("[file] receiving %s"), (LPCTSTR)path);
    m_status.SetWindowText(s);
}

void CArkDlg::AppendFileEntry(bool isDir, ULONGLONG size, const CString& name)
{
    if (m_filePending.IsEmpty() || name.IsEmpty()) return;
    FileEntry e;
    e.isDir = isDir;
    e.size  = size;
    e.name  = name;
    m_fileIncoming.push_back(std::move(e));
}

void CArkDlg::EndFileBatch(const CString& path)
{
    auto it = m_fileTreeIndex.find(std::wstring((LPCWSTR)path));
    if (it == m_fileTreeIndex.end()) {
        Log(_T("[file] batch end for unknown path=%s"), (LPCTSTR)path);
        m_filePending.Empty();
        m_fileIncoming.clear();
        return;
    }

    HTREEITEM dir = it->second;
    // Replace any previous children (incl. dummy placeholder).
    while (HTREEITEM c = m_fileTree.GetChildItem(dir)) {
        // Forget any stale path index entries for the subtree.
        m_fileTreeIndex.erase(std::wstring((LPCWSTR)GetTreeItemPath(c)));
        m_fileEntries.erase(c);
        m_fileLoaded.erase(c);
        m_fileTree.DeleteItem(c);
    }

    // Insert directory children into the tree (with a dummy placeholder so
    // they show an expand arrow). Files remain in the side list only.
    for (const FileEntry& e : m_fileIncoming) {
        if (!e.isDir) continue;
        HTREEITEM child = m_fileTree.InsertItem(e.name, dir, TVI_LAST);
        m_fileTree.InsertItem(_T("..."), child, TVI_LAST);
        m_fileTreeIndex[std::wstring((LPCWSTR)JoinPath(path, e.name))] = child;
    }

    m_fileEntries[dir] = std::move(m_fileIncoming);
    m_fileLoaded[dir] = true;
    m_fileIncoming.clear();
    m_filePending.Empty();

    if (m_fileTree.GetSelectedItem() == dir) {
        PopulateFileList(dir);
    }

    CString s;
    s.Format(_T("[file] %s: %d entries"), (LPCTSTR)path,
             (int)m_fileEntries[dir].size());
    m_status.SetWindowText(s);
    Log(_T("%s"), (LPCTSTR)s);
}

void CArkDlg::PopulateFileList(HTREEITEM dirItem)
{
    m_fileList.DeleteAllItems();
    auto it = m_fileEntries.find(dirItem);
    if (it == m_fileEntries.end()) return;

    int row = 0;
    for (const FileEntry& e : it->second) {
        int r = m_fileList.InsertItem(row++, e.name);
        if (e.isDir) {
            m_fileList.SetItemText(r, 1, _T(""));
            m_fileList.SetItemText(r, 2, _T("<DIR>"));
        } else {
            CString sz;
            if (e.size < 1024)             sz.Format(_T("%llu B"),  e.size);
            else if (e.size < 1024 * 1024) sz.Format(_T("%.1f KB"), e.size / 1024.0);
            else if (e.size < 1024 * 1024ULL * 1024) sz.Format(_T("%.2f MB"), e.size / (1024.0 * 1024.0));
            else                            sz.Format(_T("%.2f GB"), e.size / (1024.0 * 1024.0 * 1024.0));
            m_fileList.SetItemText(r, 1, sz);
            m_fileList.SetItemText(r, 2, _T("File"));
        }
    }
}

void CArkDlg::OnTreeItemExpanding(NMHDR* pNMHDR, LRESULT* pResult)
{
    NMTREEVIEW* p = reinterpret_cast<NMTREEVIEW*>(pNMHDR);
    *pResult = 0;
    if (p->action != TVE_EXPAND) return;

    HTREEITEM item = p->itemNew.hItem;
    if (m_fileLoaded.find(item) != m_fileLoaded.end()) return;  // already populated

    CString path = GetTreeItemPath(item);
    if (path.IsEmpty()) return;
    RequestFileEnum(path);
}

void CArkDlg::OnTreeSelChanged(NMHDR* pNMHDR, LRESULT* pResult)
{
    NMTREEVIEW* p = reinterpret_cast<NMTREEVIEW*>(pNMHDR);
    *pResult = 0;
    HTREEITEM item = p->itemNew.hItem;
    if (!item) {
        m_fileList.DeleteAllItems();
        return;
    }
    if (m_fileLoaded.find(item) == m_fileLoaded.end()) {
        // Not loaded yet; request enum, the file list will populate on E.
        m_fileList.DeleteAllItems();
        RequestFileEnum(GetTreeItemPath(item));
        return;
    }
    PopulateFileList(item);
}

// ---- download / upload --------------------------------------------------

CString CArkDlg::CurrentTreePath() const
{
    CTreeCtrl& t = const_cast<CTreeCtrl&>(m_fileTree);
    HTREEITEM sel = t.GetSelectedItem();
    return sel ? GetTreeItemPath(sel) : CString();
}

void CArkDlg::OnBnClickedDownload()
{
    if (CurrentTab() != 2) {
        m_status.SetWindowText(_T("[file] switch to file tab first"));
        return;
    }
    int row = m_fileList.GetNextItem(-1, LVNI_SELECTED);
    if (row < 0) {
        m_status.SetWindowText(_T("[get] select a file in the list first"));
        return;
    }
    CString type = m_fileList.GetItemText(row, 2);
    if (type == _T("<DIR>")) {
        m_status.SetWindowText(_T("[get] cannot download a directory"));
        return;
    }
    CString name = m_fileList.GetItemText(row, 0);
    CString remoteDir = CurrentTreePath();
    if (remoteDir.IsEmpty()) {
        m_status.SetWindowText(_T("[get] select the parent directory in the tree"));
        return;
    }
    CString remotePath = JoinPath(remoteDir, name);

    CFileDialog dlg(FALSE, NULL, name,
        OFN_OVERWRITEPROMPT | OFN_HIDEREADONLY,
        _T("All files (*.*)|*.*||"), this);
    if (dlg.DoModal() != IDOK) return;
    m_dlLocalPath = dlg.GetPathName();

    if (m_dlFile != INVALID_HANDLE_VALUE) {
        CloseHandle(m_dlFile);
        m_dlFile = INVALID_HANDLE_VALUE;
    }

    CStringA pathUtf8 = WToUtf8(remotePath);
    CStringA cmd;
    cmd.Format("%s%s\n", NETDRV_CMD_GET_FILE, (LPCSTR)pathUtf8);
    if (m_udp && m_udp->SendCommand(cmd)) {
        ++m_txCommands;
        m_dlRemotePath = remotePath;
        m_dlReceived = 0;
        m_dlChunks = 0;
        m_dlTotal = 0;
        m_dlRetries = 0;
        CString s;
        s.Format(_T("[get] requested %s -> %s"), (LPCTSTR)remotePath, (LPCTSTR)m_dlLocalPath);
        m_status.SetWindowText(s);
        Log(_T("%s"), (LPCTSTR)s);
    } else {
        m_status.SetWindowText(_T("[get] UDP send failed"));
    }
}

void CArkDlg::BeginDownload(const CString& remotePath, const CString& localPath, ULONGLONG total)
{
    UNREFERENCED_PARAMETER(remotePath);
    if (localPath.IsEmpty()) return;
    if (m_dlFile != INVALID_HANDLE_VALUE) {
        CloseHandle(m_dlFile);
        m_dlFile = INVALID_HANDLE_VALUE;
    }
    m_dlFile = CreateFile(localPath, GENERIC_WRITE, 0, NULL,
                          CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (m_dlFile == INVALID_HANDLE_VALUE) {
        CString s;
        s.Format(_T("[get] create local file failed err=%u"), GetLastError());
        m_status.SetWindowText(s);
        Log(_T("%s"), (LPCTSTR)s);
        return;
    }
    m_dlTotal = total;
    m_dlReceived = 0;
    m_dlChunks = 0;
    CString s;
    s.Format(_T("[get] receiving %llu bytes -> %s"), total, (LPCTSTR)localPath);
    m_status.SetWindowText(s);
    Log(_T("%s"), (LPCTSTR)s);
}

void CArkDlg::AppendDownloadChunk(ULONGLONG offset, const BYTE* data, ULONG len)
{
    if (m_dlFile == INVALID_HANDLE_VALUE || !data || len == 0) return;
    LARGE_INTEGER li; li.QuadPart = (LONGLONG)offset;
    SetFilePointerEx(m_dlFile, li, NULL, FILE_BEGIN);
    DWORD wrote = 0;
    if (WriteFile(m_dlFile, data, len, &wrote, NULL) && wrote == len) {
        m_dlReceived += len;
        ++m_dlChunks;
        if ((m_dlChunks & 31) == 0) {
            CString s;
            s.Format(_T("[get] %llu / %llu"), m_dlReceived, m_dlTotal);
            m_status.SetWindowText(s);
        }
    }
}

void CArkDlg::EndDownload(ULONGLONG sentBytes)
{
    if (m_dlFile == INVALID_HANDLE_VALUE) return;
    CloseHandle(m_dlFile);
    m_dlFile = INVALID_HANDLE_VALUE;

    /* Auto-retry if incomplete (up to 3 times) */
    if (m_dlReceived < sentBytes && m_dlRetries < 3 && !m_dlRemotePath.IsEmpty()) {
        ++m_dlRetries;
        CString s;
        s.Format(_T("[get] incomplete %llu/%llu, retry %u/3 -> %s"),
                 m_dlReceived, sentBytes, m_dlRetries, (LPCTSTR)m_dlLocalPath);
        m_status.SetWindowText(s);
        Log(_T("%s"), (LPCTSTR)s);

        CStringA pathUtf8 = WToUtf8(m_dlRemotePath);
        CStringA cmd;
        cmd.Format("%s%s\n", NETDRV_CMD_GET_FILE, (LPCSTR)pathUtf8);
        m_dlReceived = 0;
        m_dlChunks = 0;
        m_dlTotal = 0;
        if (m_udp) m_udp->SendCommand(cmd);
        return;
    }

    CString s;
    if (m_dlReceived == sentBytes) {
        s.Format(_T("[get] done %llu bytes -> %s"),
                 m_dlReceived, (LPCTSTR)m_dlLocalPath);
    } else {
        s.Format(_T("[get] INCOMPLETE received=%llu reported=%llu -> %s"),
                 m_dlReceived, sentBytes, (LPCTSTR)m_dlLocalPath);
    }
    m_dlRetries = 0;
    m_status.SetWindowText(s);
    Log(_T("%s"), (LPCTSTR)s);
}

void CArkDlg::OnBnClickedUpload()
{
    if (CurrentTab() != 2) {
        m_status.SetWindowText(_T("[file] switch to file tab first"));
        return;
    }
    CString remoteDir = CurrentTreePath();
    if (remoteDir.IsEmpty()) {
        m_status.SetWindowText(_T("[put] select a target directory in the tree first"));
        return;
    }
    CFileDialog dlg(TRUE, NULL, NULL,
        OFN_HIDEREADONLY | OFN_FILEMUSTEXIST,
        _T("All files (*.*)|*.*||"), this);
    if (dlg.DoModal() != IDOK) return;
    CString local = dlg.GetPathName();

    // remote path = remoteDir + '\\' + source filename
    CString srcName = dlg.GetFileName();
    CString remotePath = JoinPath(remoteDir, srcName);
    RunUpload(local, remotePath);
}

void CArkDlg::RunUpload(const CString& localPath, const CString& remotePath)
{
    HANDLE hFile = CreateFile(localPath, GENERIC_READ, FILE_SHARE_READ,
                              NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        CString s; s.Format(_T("[put] open source failed err=%u"), GetLastError());
        m_status.SetWindowText(s); Log(_T("%s"), (LPCTSTR)s);
        return;
    }
    LARGE_INTEGER liSize = { 0 };
    GetFileSizeEx(hFile, &liSize);
    ULONGLONG total = (ULONGLONG)liSize.QuadPart;
    const UINT chunkSize = 512;
    ULONG chunkCount = (ULONG)((total + chunkSize - 1) / chunkSize);
    if (chunkCount == 0) chunkCount = 1;
    if (total > 64ULL * 1024 * 1024) {
        CloseHandle(hFile);
        m_status.SetWindowText(_T("[put] file too large (>64MB)"));
        return;
    }

    CStringA pathUtf8 = WToUtf8(remotePath);
    CStringA cmd;
    cmd.Format("%s%s|%llX|%u|%u\n", NETDRV_CMD_PUT_BEGIN,
               (LPCSTR)pathUtf8, total, chunkSize, chunkCount);
    if (!m_udp || !m_udp->SendCommand(cmd)) {
        CloseHandle(hFile);
        m_status.SetWindowText(_T("[put] UDP put-begin failed"));
        return;
    }
    ++m_txCommands;

    static const char kHex[] = "0123456789ABCDEF";
    std::vector<BYTE> buf(chunkSize);
    std::vector<char> packet(chunkSize * 2 + 64);
    ULONGLONG sent = 0;
    ULONG idx = 0;
    Sleep(10); // give driver a moment to open destination file

    while (sent < total) {
        DWORD want = (DWORD)((total - sent > chunkSize) ? chunkSize : (total - sent));
        DWORD got = 0;
        if (!ReadFile(hFile, buf.data(), want, &got, NULL) || got == 0) break;

        // hex encode
        int phLen = _snprintf_s(packet.data(), packet.size(), _TRUNCATE,
            "P|%u|%llX|%X|", idx, sent, got);
        char* dst = packet.data() + phLen;
        for (DWORD k = 0; k < got; ++k) {
            *dst++ = kHex[(buf[k] >> 4) & 0xF];
            *dst++ = kHex[buf[k] & 0xF];
        }
        *dst++ = '\n';
        *dst = 0;

        if (!m_udp->SendCommand(packet.data())) {
            Log(_T("[put] send chunk %u failed err=%u"), idx, WSAGetLastError());
            break;
        }
        sent += got;
        ++idx;
        if ((idx & 0x0F) == 0) {
            CString s;
            s.Format(_T("[put] %llu / %llu"), sent, total);
            m_status.SetWindowText(s);
            // keep UI alive
            MSG msg;
            while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
                TranslateMessage(&msg);
                DispatchMessage(&msg);
            }
            Sleep(2);
        }
    }
    CloseHandle(hFile);

    CStringA endCmd;
    endCmd.Format("%s%s|%llX\n", NETDRV_CMD_PUT_END, (LPCSTR)pathUtf8, total);
    m_udp->SendCommand(endCmd);

    CString s;
    s.Format(_T("[put] sent %llu bytes (%u chunks) -> %s"), sent, idx, (LPCTSTR)remotePath);
    m_status.SetWindowText(s);
    Log(_T("%s"), (LPCTSTR)s);
}

// ---- screenshot frame receiver ----

void CArkDlg::BeginShotFrame(const CStringA& rest)
{
    // shot|<frameId>|<w>|<h>|<totalHex>|<chunkSize>|<chunkCount>  (rest is after "shot|")
    std::vector<CStringA> f;
    int start = 0;
    for (int i = 0; i <= rest.GetLength(); ++i) {
        if (i == rest.GetLength() || rest[i] == '|') {
            f.push_back(rest.Mid(start, i - start));
            start = i + 1;
        }
    }
    if (f.size() < 6) return;

    UINT       frameId    = (UINT)_strtoui64(f[0], NULL, 10);
    UINT       width      = (UINT)_strtoui64(f[1], NULL, 10);
    UINT       height     = (UINT)_strtoui64(f[2], NULL, 10);
    size_t     totalBytes = (size_t)_strtoui64(f[3], NULL, 16);
    UINT       chunkCount = (UINT)_strtoui64(f[5], NULL, 10);

    if (width == 0 || height == 0 || totalBytes == 0 || chunkCount == 0 ||
        totalBytes != (size_t)width * height * 4 ||
        totalBytes > 64ULL * 1024 * 1024)
    {
        Log(_T("shot frame rejected id=%u %ux%u bytes=%Iu count=%u"),
            frameId, width, height, totalBytes, chunkCount);
        return;
    }

    m_shotReceiving  = true;
    m_shotFrameId    = frameId;
    m_shotWidth      = width;
    m_shotHeight     = height;
    m_shotExpected   = totalBytes;
    m_shotReceived   = 0;
    m_shotChunkCount = chunkCount;
    m_shotImage.assign(totalBytes, 0);
    m_shotChunkSeen.assign(chunkCount, 0);

    CString s;
    s.Format(_T("[shot] receiving frame %u %ux%u chunks=%u"),
             frameId, width, height, chunkCount);
    m_status.SetWindowText(s);
    Log(_T("%s"), (LPCTSTR)s);
}

void CArkDlg::AppendShotChunk(const CStringA& rest)
{
    // <frameId>|<idx>|<offHex>|<lenHex>|<dataHex>
    if (!m_shotReceiving) return;

    std::vector<CStringA> f;
    int start = 0;
    for (int i = 0; i <= rest.GetLength(); ++i) {
        if (i == rest.GetLength() || rest[i] == '|') {
            f.push_back(rest.Mid(start, i - start));
            start = i + 1;
            if (f.size() == 4) { f.push_back(rest.Mid(i + 1)); break; }
        }
    }
    if (f.size() < 5) return;

    UINT       frameId = (UINT)_strtoui64(f[0], NULL, 10);
    UINT       idx     = (UINT)_strtoui64(f[1], NULL, 10);
    ULONGLONG  off     = (ULONGLONG)_strtoui64(f[2], NULL, 16);
    ULONG      len     = (ULONG)_strtoui64(f[3], NULL, 16);
    const CStringA& hex = f[4];

    if (frameId != m_shotFrameId || idx >= m_shotChunkCount ||
        (size_t)(off + len) > m_shotImage.size() ||
        (int)(len * 2) > hex.GetLength()) return;

    if (m_shotChunkSeen[idx]) return;

    BYTE* dst = m_shotImage.data() + off;
    for (ULONG k = 0; k < len; ++k) {
        int hi = (hex[k * 2]     >= 'a') ? hex[k * 2]     - 'a' + 10 :
                 (hex[k * 2]     >= 'A') ? hex[k * 2]     - 'A' + 10 : hex[k * 2]     - '0';
        int lo = (hex[k * 2 + 1] >= 'a') ? hex[k * 2 + 1] - 'a' + 10 :
                 (hex[k * 2 + 1] >= 'A') ? hex[k * 2 + 1] - 'A' + 10 : hex[k * 2 + 1] - '0';
        dst[k] = (BYTE)((hi << 4) | lo);
    }
    m_shotChunkSeen[idx] = 1;
    m_shotReceived += len;
}

void CArkDlg::EndShotFrame(const CStringA& rest)
{
    // <frameId>|<sentBytes>
    if (!m_shotReceiving) return;
    int p1 = rest.Find('|');
    UINT frameId = (UINT)_strtoui64(rest.Left(p1 > 0 ? p1 : rest.GetLength()), NULL, 10);
    if (frameId != m_shotFrameId) return;

    bool complete = (m_shotReceived == m_shotExpected);
    m_shotReceiving = false;

    if (!complete) {
        CString s;
        s.Format(_T("[shot] frame %u incomplete %Iu/%Iu"),
                 frameId, m_shotReceived, m_shotExpected);
        m_status.SetWindowText(s);
        Log(_T("%s"), (LPCTSTR)s);
        return;
    }

    RenderShotToView();
    CString s;
    s.Format(_T("[shot] frame %u %ux%u rendered (%Iu bytes)"),
             frameId, m_shotWidth, m_shotHeight, m_shotExpected);
    m_status.SetWindowText(s);
    Log(_T("%s"), (LPCTSTR)s);

    /* Auto-request next frame for live view */
    if (m_shotLive && CurrentTab() == 3) {
        SetTimer(100, 33, NULL);  /* ~30 FPS */
    }
}

void CArkDlg::ClearShotBitmap()
{
    if (::IsWindow(m_shotView.GetSafeHwnd())) {
        HBITMAP old = (HBITMAP)m_shotView.SetBitmap(NULL);
        if (old) DeleteObject(old);
    } else if (m_hShotBitmap) {
        DeleteObject(m_hShotBitmap);
    }
    m_hShotBitmap = NULL;
}

void CArkDlg::RenderShotToView()
{
    if (!::IsWindow(m_shotView.GetSafeHwnd()) || m_shotImage.empty()) return;
    if (m_shotWidth == 0 || m_shotHeight == 0) return;

    CRect rc;
    m_shotView.GetClientRect(&rc);
    int dstW = max(1, rc.Width());
    int dstH = max(1, rc.Height());

    HDC hScreen = ::GetDC(NULL);
    if (!hScreen) return;
    HDC hMem = CreateCompatibleDC(hScreen);
    HBITMAP hBmp = hMem ? CreateCompatibleBitmap(hScreen, dstW, dstH) : NULL;
    if (!hMem || !hBmp) {
        if (hMem) DeleteDC(hMem);
        ::ReleaseDC(NULL, hScreen);
        return;
    }

    HGDIOBJ old = SelectObject(hMem, hBmp);
    RECT fill = { 0, 0, dstW, dstH };
    FillRect(hMem, &fill, (HBRUSH)GetStockObject(BLACK_BRUSH));

    BITMAPINFO bi = { 0 };
    bi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bi.bmiHeader.biWidth = (LONG)m_shotWidth;
    bi.bmiHeader.biHeight = -(LONG)m_shotHeight;   // top-down BGRA
    bi.bmiHeader.biPlanes = 1;
    bi.bmiHeader.biBitCount = 32;
    bi.bmiHeader.biCompression = BI_RGB;

    SetStretchBltMode(hMem, HALFTONE);
    SetBrushOrgEx(hMem, 0, 0, NULL);
    StretchDIBits(hMem,
                  0, 0, dstW, dstH,
                  0, 0, (int)m_shotWidth, (int)m_shotHeight,
                  m_shotImage.data(), &bi, DIB_RGB_COLORS, SRCCOPY);
    SelectObject(hMem, old);
    DeleteDC(hMem);
    ::ReleaseDC(NULL, hScreen);

    ClearShotBitmap();
    m_hShotBitmap = hBmp;
    m_shotView.SetBitmap(hBmp);
    m_shotView.Invalidate(FALSE);
}
