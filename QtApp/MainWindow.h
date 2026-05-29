#pragma once
#include <QMainWindow>
#include <QTabWidget>
#include <QTableWidget>
#include <QTreeWidget>
#include <QLabel>
#include <QPushButton>
#include <QProgressBar>
#include <QStatusBar>
#include <QTimer>
#include <QFile>
#include <QMap>
#include "UdpLink.h"
#include "TcpLink.h"

class MainWindow : public QMainWindow
{
    Q_OBJECT
public:
    explicit MainWindow(QWidget* parent = nullptr);

private slots:
    void onDriverConnected(const QString& ip, quint16 port);
    void onPacket(const QByteArray& payload);
    void onRefresh();
    void onDownload();
    void onUpload();
    void onTreeExpanded(QTreeWidgetItem* item);
    void onTreeSelected();
    void onShotTimer();
    void pumpUpload();

private:
    void handleLine(const QByteArray& line);
    void setStatus(const QString& msg);

    // screenshot
    void beginShotFrame(const QByteArray& rest);
    void appendShotChunk(const QByteArray& rest);
    void appendShotChunkV2(const QByteArray& binPayload);
    void endShotFrame(const QByteArray& rest);
    void renderShot();
    static QByteArray rleDecompress(const QByteArray& comp, quint32 dwordCount);

    // file browser
    void initFileTree();
    void requestFileEnum(const QString& path);
    void beginFileBatch(const QString& path);
    void appendFileEntry(bool isDir, quint64 size, const QString& name);
    void endFileBatch(const QString& path);
    void populateFileList(QTreeWidgetItem* item);
    QString treePath(QTreeWidgetItem* item) const;

    // download
    void beginDownload(quint64 total);
    void appendDownloadChunk(quint64 off, const QByteArray& data);
    void endDownload(quint64 reported);

    // upload
    void resetUpload();
    void finishUpload();

    // helpers
    static QByteArray hexDecode(const QByteArray& hex);
    static QString hexToUtf8(const QByteArray& hex);
    int currentTab() const { return m_tabs->currentIndex(); }
    QString ntPathToDos(const QString& nt) const;
    void buildDriveMap();
    static QString queryFileVendor(const QString& dosPath);
    static QString queryFileSign(const QString& dosPath);

    // UI
    QTabWidget*    m_tabs;
    QTableWidget*  m_procTable;
    QTableWidget*  m_drvTable;
    QTreeWidget*   m_fileTree;
    QTableWidget*  m_fileList;
    QLabel*        m_shotLabel;
    QPushButton*   m_btnRefresh;
    QPushButton*   m_btnDownload;
    QPushButton*   m_btnUpload;
    QProgressBar*  m_progressBar;
    QLabel*        m_progressLabel;

    // networking
    UdpLink*       m_udp;     // legacy UDP (kept, not active)
    TcpLink*       m_tcp;     // primary TCP link

    // screenshot state
    QTimer*        m_shotTimer;
    bool           m_shotLive      = false;
    bool           m_shotReceiving = false;
    uint           m_shotFrameId   = 0;
    uint           m_shotWidth     = 0;
    uint           m_shotHeight    = 0;
    size_t         m_shotExpected  = 0;
    size_t         m_shotReceived  = 0;
    uint           m_shotChunkCount = 0;
    QByteArray     m_shotImage;
    QVector<bool>  m_shotChunkSeen;

    // V2 (diff+RLE+binary) state
    bool           m_shotV2        = false;
    bool           m_shotIsKey     = false;
    size_t         m_shotCompSize  = 0;
    size_t         m_shotCompRecv  = 0;
    QByteArray     m_shotCompBuf;
    QByteArray     m_shotPrevImage;

    // file browser state
    struct FileEntry { bool isDir; quint64 size; QString name; };
    QMap<QString, QTreeWidgetItem*>           m_treeIndex;
    QMap<QTreeWidgetItem*, QVector<FileEntry>> m_fileEntries;
    QSet<QTreeWidgetItem*>                    m_fileLoaded;
    QString                                   m_filePending;
    QVector<FileEntry>                        m_fileIncoming;

    // download state
    QFile*         m_dlFile       = nullptr;
    QString        m_dlRemotePath;
    QString        m_dlLocalPath;
    quint64        m_dlTotal      = 0;
    quint64        m_dlReceived   = 0;
    uint           m_dlRetries    = 0;

    // upload state
    QTimer*        m_uploadTimer  = nullptr;
    QFile*         m_ulFile       = nullptr;
    QString        m_ulRemotePath;
    QString        m_ulFileName;
    quint64        m_ulTotal      = 0;
    quint64        m_ulSent       = 0;
    uint           m_ulChunkSize  = 8192;
    uint           m_ulChunkCount = 0;
    uint           m_ulIndex      = 0;
    bool           m_ulActive     = false;

    // process rows
    QMap<uint, int> m_processRows;

    // drive letter map: NT path prefix -> drive letter
    QVector<QPair<QString,QString>> m_driveMap;
};
