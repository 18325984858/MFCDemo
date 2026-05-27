#pragma once
#include "ArkUdp.h"

class CArkDlg : public CDialogEx
{
public:
    CArkDlg(CWnd* pParent = nullptr);
    enum { IDD = 100 };

    void Log(LPCTSTR format, ...);

    // Called by CArkUdp for every parsed line (ASCII).
    void OnArkLine(const CStringA& line);
    void OnArkPacket(const char* payload, int payloadLen);

protected:
    virtual void DoDataExchange(CDataExchange* pDX) override;
    virtual BOOL OnInitDialog() override;
    afx_msg void OnBnClickedRefresh();
    afx_msg void OnBnClickedDownload();
    afx_msg void OnBnClickedUpload();
    afx_msg void OnTabSelChange(NMHDR* pNMHDR, LRESULT* pResult);
    afx_msg void OnTreeItemExpanding(NMHDR* pNMHDR, LRESULT* pResult);
    afx_msg void OnTreeSelChanged(NMHDR* pNMHDR, LRESULT* pResult);
    afx_msg void OnSize(UINT nType, int cx, int cy);
    afx_msg void OnGetMinMaxInfo(MINMAXINFO* lpMMI);
    afx_msg void OnTimer(UINT_PTR nIDEvent);
    afx_msg void OnDestroy();
    DECLARE_MESSAGE_MAP()

private:
    void SendDriverCommand(LPCSTR command, LPCTSTR label);
    int  CurrentTab() const;
    // Translate "\Device\HarddiskVolumeN\..." or "\SystemRoot\..." or
    // "\??\..." into a DOS path ("C:\..."). Leaves DOS paths unchanged.
    CString NtPathToDos(const CString& nt) const;
    void    BuildDriveLetterMap();
    void    ApplyProcessExtra(const CStringA& rest);
    void    UpdateTabVisibility();

    // File tab helpers.
    void       InitFileTab();
    void       RequestFileEnum(const CString& path);
    void       BeginFileBatch(const CString& path);
    void       AppendFileEntry(bool isDir, ULONGLONG size, const CString& name);
    void       EndFileBatch(const CString& path);
    void       PopulateFileList(HTREEITEM dirItem);
    CString    GetTreeItemPath(HTREEITEM item) const;
    static CString JoinPath(const CString& parent, const CString& name);

    // download / upload
    CString    CurrentTreePath() const;
    void       BeginDownload(const CString& remotePath, const CString& localPath, ULONGLONG total);
    void       AppendDownloadChunk(ULONGLONG offset, const BYTE* data, ULONG len);
    void       EndDownload(ULONGLONG sentBytes);
    void       RunUpload(const CString& localPath, const CString& remotePath);

    CTabCtrl  m_tab;
    CListCtrl m_listProc;
    CListCtrl m_listDrv;
    CTreeCtrl m_fileTree;
    CListCtrl m_fileList;
    CStatic   m_shotView;
    CStatic   m_status;
    std::unique_ptr<CArkUdp> m_udp;

    bool      m_inProcBatch = false;
    bool      m_inDrvBatch  = false;
    UINT      m_txCommands  = 0;
    UINT      m_rxLines     = 0;
    CString   m_logPath;
    ULONG_PTR m_gdiplusToken = 0;

    std::unordered_map<DWORD, int> m_processRows;

    // letter ("C:") -> NT target ("\Device\HarddiskVolume3")
    std::vector<std::pair<CString, CString>> m_driveMap;

    // ---- file tab state ----
    struct FileEntry { bool isDir = false; ULONGLONG size = 0; CString name; };
    std::unordered_map<std::wstring, HTREEITEM>    m_fileTreeIndex;   // path -> tree item
    std::unordered_map<HTREEITEM, std::vector<FileEntry>> m_fileEntries; // dir -> entries
    std::unordered_map<HTREEITEM, bool>            m_fileLoaded;      // dir -> children loaded
    CString    m_filePending;
    std::vector<FileEntry>                          m_fileIncoming;

    // ---- download state ----
    HANDLE     m_dlFile        = INVALID_HANDLE_VALUE;
    CString    m_dlRemotePath;
    CString    m_dlLocalPath;
    ULONGLONG  m_dlTotal       = 0;
    ULONGLONG  m_dlReceived    = 0;
    UINT       m_dlChunks      = 0;
    UINT       m_dlRetries     = 0;

    // ---- screenshot frame receiver ----
    void       BeginShotFrame(const CStringA& rest);
    void       AppendShotChunk(const CStringA& rest);
    void       EndShotFrame(const CStringA& rest);
    void       RenderShotToView();
    void       ClearShotBitmap();
    bool       m_shotReceiving = false;
    UINT       m_shotFrameId   = 0;
    UINT       m_shotWidth     = 0;
    UINT       m_shotHeight    = 0;
    size_t     m_shotExpected  = 0;
    size_t     m_shotReceived  = 0;
    UINT       m_shotChunkCount = 0;
    std::vector<BYTE> m_shotImage;
    std::vector<BYTE> m_shotChunkSeen;
    HBITMAP    m_hShotBitmap   = NULL;
    bool       m_shotLive      = false;
};
