#include "MainWindow.h"
#include "Ioctl.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QSplitter>
#include <QHeaderView>
#include <QFileDialog>
#include <QFileInfo>
#include <QMessageBox>
#include <QDateTime>
#include <QImage>
#include <QPixmap>
#include <QDebug>
#include <QApplication>
#include <QThread>

#ifdef Q_OS_WIN
#include <windows.h>
#include <wintrust.h>
#include <softpub.h>
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "version.lib")
#endif

// ---- shot diagnostic log ----
#include <cstdio>
#include <cstdarg>
static FILE* g_shotLog = nullptr;
static void shotLog(const char* fmt, ...)
{
    if (!g_shotLog) {
        g_shotLog = fopen("shot_log.txt", "w");
        if (!g_shotLog) return;
    }
    va_list ap;
    va_start(ap, fmt);
    vfprintf(g_shotLog, fmt, ap);
    va_end(ap);
    fputc('\n', g_shotLog);
    fflush(g_shotLog);
}

// ---- helpers ----

QByteArray MainWindow::hexDecode(const QByteArray& hex)
{
    return QByteArray::fromHex(hex);
}

QString MainWindow::hexToUtf8(const QByteArray& hex)
{
    QByteArray raw = QByteArray::fromHex(hex);
    return QString::fromUtf8(raw);
}

void MainWindow::buildDriveMap()
{
#ifdef Q_OS_WIN
    m_driveMap.clear();
    WCHAR drives[256] = {};
    DWORD n = GetLogicalDriveStringsW(255, drives);
    for (LPWSTR d = drives; *d; d += wcslen(d) + 1) {
        WCHAR letter[3] = { d[0], L':', 0 };
        WCHAR target[MAX_PATH] = {};
        if (QueryDosDeviceW(letter, target, MAX_PATH)) {
            m_driveMap.append({QString::fromWCharArray(target),
                              QString::fromWCharArray(letter)});
        }
    }
#endif
}

QString MainWindow::ntPathToDos(const QString& nt) const
{
    if (nt.isEmpty() || nt == "-") return nt;
    if (nt.startsWith("\\SystemRoot\\", Qt::CaseInsensitive)) {
#ifdef Q_OS_WIN
        WCHAR winDir[MAX_PATH];
        GetWindowsDirectoryW(winDir, MAX_PATH);
        return QString::fromWCharArray(winDir) + "\\" + nt.mid(12);
#endif
    }
    if (nt.startsWith("\\??\\" )) return nt.mid(4);
    for (const auto& kv : m_driveMap) {
        if (nt.length() > kv.first.length() &&
            nt.startsWith(kv.first, Qt::CaseInsensitive) &&
            nt[kv.first.length()] == '\\') {
            return kv.second + nt.mid(kv.first.length());
        }
    }
    return nt;
}

QString MainWindow::queryFileVendor(const QString& dosPath)
{
#ifdef Q_OS_WIN
    std::wstring ws = dosPath.toStdWString();
    DWORD dummy = 0;
    DWORD sz = GetFileVersionInfoSizeW(ws.c_str(), &dummy);
    if (sz == 0) return "-";
    QByteArray buf(sz, 0);
    if (!GetFileVersionInfoW(ws.c_str(), 0, sz, buf.data())) return "-";
    struct { WORD lang; WORD cp; } *trans = nullptr;
    UINT transLen = 0;
    VerQueryValueW(buf.data(), L"\\VarFileInfo\\Translation", (void**)&trans, &transLen);
    if (!trans || transLen < sizeof(*trans)) return "-";
    wchar_t subBlock[128];
    wsprintfW(subBlock, L"\\StringFileInfo\\%04x%04x\\CompanyName", trans->lang, trans->cp);
    wchar_t* val = nullptr;
    UINT valLen = 0;
    if (VerQueryValueW(buf.data(), subBlock, (void**)&val, &valLen) && val && valLen > 0)
        return QString::fromWCharArray(val, valLen - 1);
#else
    Q_UNUSED(dosPath);
#endif
    return "-";
}

QString MainWindow::queryFileSign(const QString& dosPath)
{
#ifdef Q_OS_WIN
    std::wstring ws = dosPath.toStdWString();
    WINTRUST_FILE_INFO fi = {};
    fi.cbStruct = sizeof(fi);
    fi.pcwszFilePath = ws.c_str();
    GUID policyGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA wd = {};
    wd.cbStruct = sizeof(wd);
    wd.dwUIChoice = WTD_UI_NONE;
    wd.fdwRevocationChecks = WTD_REVOKE_NONE;
    wd.dwUnionChoice = WTD_CHOICE_FILE;
    wd.pFile = &fi;
    wd.dwStateAction = WTD_STATEACTION_VERIFY;
    wd.dwProvFlags = WTD_SAFER_FLAG | WTD_CACHE_ONLY_URL_RETRIEVAL;
    LONG r = WinVerifyTrust(NULL, &policyGuid, &wd);
    wd.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &policyGuid, &wd);
    return (r == ERROR_SUCCESS) ? "Signed" : "Unsigned";
#else
    Q_UNUSED(dosPath);
    return "-";
#endif
}

// ---- constructor ----

MainWindow::MainWindow(QWidget* parent) : QMainWindow(parent)
{
    setWindowTitle(QStringLiteral("NetDrv ARK (Qt)  build %1 %2")
                   .arg(__DATE__).arg(__TIME__));

    auto* central = new QWidget(this);
    setCentralWidget(central);
    auto* vbox = new QVBoxLayout(central);
    vbox->setContentsMargins(4,4,4,4);
    vbox->setSpacing(4);

    // top bar: buttons
    auto* topBar = new QHBoxLayout;
    topBar->addStretch();
    m_btnUpload   = new QPushButton("Upload");
    m_btnDownload = new QPushButton("Download");
    m_btnRefresh  = new QPushButton("Refresh");
    topBar->addWidget(m_btnUpload);
    topBar->addWidget(m_btnDownload);
    topBar->addWidget(m_btnRefresh);
    vbox->addLayout(topBar);

    // tabs
    m_tabs = new QTabWidget;
    vbox->addWidget(m_tabs, 1);

    // Tab 0: Process
    m_procTable = new QTableWidget;
    m_procTable->setColumnCount(11);
    m_procTable->setHorizontalHeaderLabels({
        "Image","PID","PPID","Session","User","Path",
        "EPROCESS","Sign","Vendor","Created","CmdLine"});
    m_procTable->horizontalHeader()->setStretchLastSection(true);
    m_procTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_procTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_tabs->addTab(m_procTable, "Process");

    // Tab 1: Driver
    m_drvTable = new QTableWidget;
    m_drvTable->setColumnCount(10);
    m_drvTable->setHorizontalHeaderLabels({
        "Driver","Base","Size","Order","DrvObj",
        "ObjName","Service","Sign","Company","Path"});
    m_drvTable->horizontalHeader()->setStretchLastSection(true);
    m_drvTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_drvTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_tabs->addTab(m_drvTable, "Driver");

    // Tab 2: File browser (tree + list splitter)
    auto* fileSplitter = new QSplitter(Qt::Horizontal);
    m_fileTree = new QTreeWidget;
    m_fileTree->setHeaderLabel("Path");
    m_fileList = new QTableWidget;
    m_fileList->setColumnCount(3);
    m_fileList->setHorizontalHeaderLabels({"Name","Size","Type"});
    m_fileList->horizontalHeader()->setStretchLastSection(true);
    m_fileList->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_fileList->setEditTriggers(QAbstractItemView::NoEditTriggers);
    fileSplitter->addWidget(m_fileTree);
    fileSplitter->addWidget(m_fileList);
    fileSplitter->setStretchFactor(0, 1);
    fileSplitter->setStretchFactor(1, 2);
    m_tabs->addTab(fileSplitter, "File");

    // Tab 3: Screenshot
    m_shotLabel = new QLabel;
    m_shotLabel->setAlignment(Qt::AlignCenter);
    m_shotLabel->setStyleSheet("background-color: black;");
    m_shotLabel->setMinimumSize(320, 200);
    m_tabs->addTab(m_shotLabel, "Screenshot");

    // Progress area: label + bar, below tabs
    m_progressLabel = new QLabel;
    m_progressLabel->setAlignment(Qt::AlignLeft | Qt::AlignVCenter);
    m_progressLabel->setStyleSheet("font-size: 11px; padding-left: 4px;");
    m_progressLabel->hide();
    m_progressBar = new QProgressBar;
    m_progressBar->setTextVisible(false);
    m_progressBar->setFixedHeight(16);
    m_progressBar->hide();
    vbox->addWidget(m_progressLabel);
    vbox->addWidget(m_progressBar);

    // status bar
    statusBar()->showMessage("Waiting for driver connection...");

    // connections
    connect(m_btnRefresh,  &QPushButton::clicked, this, &MainWindow::onRefresh);
    connect(m_btnDownload, &QPushButton::clicked, this, &MainWindow::onDownload);
    connect(m_btnUpload,   &QPushButton::clicked, this, &MainWindow::onUpload);
    connect(m_fileTree, &QTreeWidget::itemExpanded,
            this, &MainWindow::onTreeExpanded);
    connect(m_fileTree, &QTreeWidget::itemSelectionChanged,
            this, &MainWindow::onTreeSelected);

    // screenshot timer
    m_shotTimer = new QTimer(this);
    connect(m_shotTimer, &QTimer::timeout, this, &MainWindow::onShotTimer);

    // upload pump: keeps file transfer from flooding the TCP write buffer
    m_uploadTimer = new QTimer(this);
    m_uploadTimer->setInterval(10);
    connect(m_uploadTimer, &QTimer::timeout, this, &MainWindow::pumpUpload);

    // UDP (legacy — kept but not started)
    m_udp = new UdpLink(this);
    // m_udp->start("0.0.0.0", NETDRV_UDP_PORT);  // disabled: using TCP now

    // TCP — primary link
    m_tcp = new TcpLink(this);
    connect(m_tcp, &TcpLink::driverConnected,
            this, &MainWindow::onDriverConnected);
    connect(m_tcp, &TcpLink::packetReceived,
            this, &MainWindow::onPacket);
    connect(m_tcp, &TcpLink::fileBytesWritten, this, [this](qint64){
        if (m_ulActive && !m_uploadTimer->isActive())
            m_uploadTimer->start();
    });
    m_tcp->startServer("0.0.0.0", NETDRV_TCP_PORT);

    buildDriveMap();
    initFileTree();
}

void MainWindow::setStatus(const QString& msg)
{
    statusBar()->showMessage(msg);
}

// ---- driver connection ----

void MainWindow::onDriverConnected(const QString& ip, quint16 port)
{
    setStatus(QString("Driver connected: %1:%2").arg(ip).arg(port));
}

// ---- packet dispatch ----

void MainWindow::onPacket(const QByteArray& payload)
{
    // Binary shot chunk: Z| prefix — do NOT split by \n
    if (payload.size() >= 18 && payload[0] == 'Z' && payload[1] == '|') {
        appendShotChunkV2(payload);
        return;
    }

    // split by newlines
    int start = 0;
    for (int i = 0; i <= payload.size(); ++i) {
        if (i == payload.size() || payload[i] == '\n') {
            QByteArray line = payload.mid(start, i - start);
            if (line.endsWith('\r')) line.chop(1);
            if (!line.isEmpty()) handleLine(line);
            start = i + 1;
        }
    }
}

void MainWindow::handleLine(const QByteArray& line)
{
    if (line.size() < 2 || line[1] != '|') return;
    char tag = line[0];
    QByteArray rest = line.mid(2);

    if (tag == 'B') {
        if (rest == "process") {
            m_procTable->setRowCount(0);
            m_processRows.clear();
        } else if (rest == "driver") {
            m_drvTable->setRowCount(0);
        } else if (rest.startsWith("file|")) {
            beginFileBatch(hexToUtf8(rest.mid(5)));
        } else if (rest.startsWith("shot|")) {
            beginShotFrame(rest.mid(5));
        } else if (rest.startsWith("shot2|")) {
            beginShotFrame(rest.mid(6));
        } else if (rest.startsWith("get|")) {
            // B|get|pathHex|totalHex|chunkSize|chunkCount
            auto parts = rest.mid(4).split('|');
            if (parts.size() >= 2) {
                quint64 total = parts[1].toULongLong(nullptr, 16);
                beginDownload(total);
            }
        }
        return;
    }

    if (tag == 'E') {
        if (rest.startsWith("file|")) {
            int sep = rest.indexOf('|', 5);
            QByteArray hex = (sep > 0) ? rest.mid(5, sep - 5) : rest.mid(5);
            endFileBatch(hexToUtf8(hex));
        } else if (rest.startsWith("shot|")) {
            endShotFrame(rest.mid(5));
        } else if (rest.startsWith("shot2|")) {
            endShotFrame(rest.mid(6));
        } else if (rest.startsWith("get|")) {
            int p = rest.lastIndexOf('|');
            quint64 sent = (p > 0) ? rest.mid(p+1).toULongLong() : 0;
            endDownload(sent);
        } else {
            setStatus(QString("[%1] batch end").arg(QString::fromLatin1(rest)));
        }
        return;
    }

    if (tag == 'Y') { appendShotChunk(rest); return; }

    if (tag == 'G') {
        // G|idx|offsetHex|lenHex|dataHex
        auto parts = rest.split('|');
        if (parts.size() >= 4) {
            quint64 off = parts[1].toULongLong(nullptr, 16);
            QByteArray data = hexDecode(parts[3]);
            appendDownloadChunk(off, data);
        }
        return;
    }

    if (tag == 'F') {
        auto parts = rest.split('|');
        if (parts.size() >= 3) {
            bool isDir = (parts[0] == "1");
            quint64 sz = parts[1].toULongLong(nullptr, 16);
            appendFileEntry(isDir, sz, hexToUtf8(parts[2]));
        }
        return;
    }

    if (tag == 'S') {
        setStatus(QString::fromUtf8(rest));
        return;
    }

    if (tag == 'U') {
        // U|pid|userHex|cmdHex
        auto parts = rest.split('|');
        if (parts.size() >= 3) {
            uint pid = parts[0].toUInt();
            auto it = m_processRows.find(pid);
            if (it != m_processRows.end()) {
                int row = it.value();
                QString user = hexToUtf8(parts[1]);
                QString cmd  = hexToUtf8(parts[2]);
                if (user != "-") m_procTable->item(row, 4)->setText(user);
                if (cmd  != "-") m_procTable->item(row, 10)->setText(cmd);
            }
        }
        return;
    }

    if (tag == 'P') {
        // P|pid|ppid|session|eprocess|createTime|name|path
        // path may contain '|', so limit split to 7 fields
        int fieldCount = 0;
        int splits[7];
        for (int i = 0; i < rest.size() && fieldCount < 6; ++i) {
            if (rest[i] == '|') splits[fieldCount++] = i;
        }
        if (fieldCount < 6) return;
        QByteArray f0 = rest.left(splits[0]);
        QByteArray f1 = rest.mid(splits[0]+1, splits[1]-splits[0]-1);
        QByteArray f2 = rest.mid(splits[1]+1, splits[2]-splits[1]-1);
        QByteArray f3 = rest.mid(splits[2]+1, splits[3]-splits[2]-1);
        QByteArray f4 = rest.mid(splits[3]+1, splits[4]-splits[3]-1);
        QByteArray f5 = rest.mid(splits[4]+1, splits[5]-splits[4]-1);
        QByteArray f6 = rest.mid(splits[5]+1); // path = remainder

        int row = m_procTable->rowCount();
        m_procTable->insertRow(row);
        QString name = QString::fromUtf8(f5);
        QString ntPath = QString::fromUtf8(f6).trimmed();
        QString dosPath = ntPathToDos(ntPath);
        uint pid = f0.toUInt();

        // createTime: 100ns since 1601 -> QDateTime
        qint64 ft = f4.toLongLong();
        QString ctime = "-";
        if (ft > 0) {
            qint64 unixUs = (ft - 116444736000000000LL) / 10;
            QDateTime dt = QDateTime::fromMSecsSinceEpoch(unixUs / 1000, Qt::LocalTime);
            ctime = dt.toString("yyyy/MM/dd HH:mm:ss");
        }

        // Local enrichment: sign + vendor
        QString sign = "-", vendor = "-";
        if (!dosPath.isEmpty() && dosPath != "-") {
            sign   = queryFileSign(dosPath);
            vendor = queryFileVendor(dosPath);
        }

        auto set = [&](int col, const QString& val) {
            m_procTable->setItem(row, col, new QTableWidgetItem(val));
        };
        set(0, name);
        set(1, QString::fromLatin1(f0));
        set(2, QString::fromLatin1(f1));
        set(3, QString::fromLatin1(f2));
        set(4, "-");  // user (filled by U|)
        set(5, dosPath);
        set(6, QString::fromLatin1(f3));
        set(7, sign);
        set(8, vendor);
        set(9, ctime);
        set(10, "-"); // cmdline (filled by U|)

        m_processRows[pid] = row;
        if ((row + 1) % 50 == 0)
            setStatus(QString("[process] %1 rows").arg(row + 1));
        return;
    }

    if (tag == 'D') {
        // D|name|base|size|order|drvObj|objName|svc|path
        // path is last field and may contain '|', so limit split
        int fc = 0;
        int sp[8];
        for (int i = 0; i < rest.size() && fc < 7; ++i) {
            if (rest[i] == '|') sp[fc++] = i;
        }
        if (fc < 7) return;
        QString dName   = QString::fromUtf8(rest.left(sp[0]));
        QString dBase   = QString::fromLatin1(rest.mid(sp[0]+1, sp[1]-sp[0]-1));
        QString dSize   = QString::fromLatin1(rest.mid(sp[1]+1, sp[2]-sp[1]-1));
        QString dOrder  = QString::fromLatin1(rest.mid(sp[2]+1, sp[3]-sp[2]-1));
        QString dObj    = QString::fromLatin1(rest.mid(sp[3]+1, sp[4]-sp[3]-1));
        QString dObjNm  = QString::fromUtf8(rest.mid(sp[4]+1, sp[5]-sp[4]-1));
        QString dSvc    = QString::fromUtf8(rest.mid(sp[5]+1, sp[6]-sp[5]-1));
        QString dPath   = ntPathToDos(QString::fromUtf8(rest.mid(sp[6]+1)));

        QString sign = "-", company = "-";
        if (!dPath.isEmpty() && dPath != "-") {
            sign    = queryFileSign(dPath);
            company = queryFileVendor(dPath);
        }

        int row = m_drvTable->rowCount();
        m_drvTable->insertRow(row);
        // Columns: Driver|Base|Size|Order|DrvObj|ObjName|Service|Sign|Company|Path
        m_drvTable->setItem(row, 0, new QTableWidgetItem(dName));
        m_drvTable->setItem(row, 1, new QTableWidgetItem(dBase));
        m_drvTable->setItem(row, 2, new QTableWidgetItem(dSize));
        m_drvTable->setItem(row, 3, new QTableWidgetItem(dOrder));
        m_drvTable->setItem(row, 4, new QTableWidgetItem(dObj));
        m_drvTable->setItem(row, 5, new QTableWidgetItem(dObjNm));
        m_drvTable->setItem(row, 6, new QTableWidgetItem(dSvc));
        m_drvTable->setItem(row, 7, new QTableWidgetItem(sign));
        m_drvTable->setItem(row, 8, new QTableWidgetItem(company));
        m_drvTable->setItem(row, 9, new QTableWidgetItem(dPath));
        return;
    }
}

// ---- button handlers ----

void MainWindow::onRefresh()
{
    if (!m_tcp->isDriverConnected()) {
        setStatus("Driver not connected");
        return;
    }
    int tab = currentTab();
    if (tab == 0) {
        m_procTable->setRowCount(0);
        m_processRows.clear();
        m_tcp->sendCommand(NETDRV_CMD_ENUM_PROCESS);
        setStatus("[process] requesting...");
    } else if (tab == 1) {
        m_drvTable->setRowCount(0);
        m_tcp->sendCommand(NETDRV_CMD_ENUM_DRIVER);
        setStatus("[driver] requesting...");
    } else if (tab == 2) {
        auto sel = m_fileTree->selectedItems();
        if (!sel.isEmpty()) {
            QString path = treePath(sel.first());
            m_fileLoaded.remove(sel.first());
            m_fileEntries.remove(sel.first());
            while (sel.first()->childCount())
                delete sel.first()->takeChild(0);
            requestFileEnum(path);
        } else {
            m_fileTree->clear();
            m_treeIndex.clear();
            m_fileEntries.clear();
            m_fileLoaded.clear();
            initFileTree();
        }
    } else if (tab == 3) {
        m_shotReceiving = false;
        m_shotImage.clear();
        m_shotChunkSeen.clear();
        m_shotLive = true;
        m_tcp->sendCommand(NETDRV_CMD_SCREENSHOT);
        setStatus("[screenshot] requesting...");
    }
}

void MainWindow::onShotTimer()
{
    if (m_shotLive && currentTab() == 3 && !m_shotReceiving) {
        m_tcp->sendCommand(NETDRV_CMD_SCREENSHOT);
    }
}

// ---- screenshot ----

void MainWindow::beginShotFrame(const QByteArray& rest)
{
    auto parts = rest.split('|');

    /* V2: fid|w|h|rawSizeHex|compSizeHex|chunkSz|chunkCnt|isKey */
    if (parts.size() >= 8) {
        uint fid    = parts[0].toUInt();
        uint w      = parts[1].toUInt();
        uint h      = parts[2].toUInt();
        size_t raw  = parts[3].toULongLong(nullptr, 16);
        size_t comp = parts[4].toULongLong(nullptr, 16);
        uint chunks = parts[6].toUInt();
        bool isKey  = parts[7].toUInt() != 0;

        if (w == 0 || h == 0 || raw == 0 || comp == 0 || chunks == 0 ||
            raw != (size_t)w * h * 4 || raw > 64ULL * 1024 * 1024)
            return;

        m_shotReceiving  = true;
        m_shotV2         = true;
        m_shotIsKey      = isKey;
        m_shotFrameId    = fid;
        m_shotWidth      = w;
        m_shotHeight     = h;
        m_shotExpected   = raw;
        m_shotCompSize   = comp;
        m_shotCompRecv   = 0;
        m_shotReceived   = 0;
        m_shotChunkCount = chunks;
        m_shotCompBuf.fill(0, (int)comp);
        m_shotChunkSeen.fill(false, chunks);
        /* Allocate image buffer (keep prev for diff) */
        m_shotImage.resize((int)raw);
        shotLog("BEGIN fid=%u %ux%u raw=%zu comp=%zu chunks=%u key=%d",
                fid, w, h, raw, comp, chunks, isKey ? 1 : 0);
        setStatus(QString("[shot2] frame %1 %2x%3 comp=%4 key=%5")
                  .arg(fid).arg(w).arg(h).arg(comp).arg(isKey));
        return;
    }

    /* V1 fallback: fid|w|h|totalHex|chunkSz|chunkCnt */
    if (parts.size() < 6) return;
    uint fid    = parts[0].toUInt();
    uint w      = parts[1].toUInt();
    uint h      = parts[2].toUInt();
    size_t total = parts[3].toULongLong(nullptr, 16);
    uint chunks = parts[5].toUInt();

    if (w == 0 || h == 0 || total == 0 || chunks == 0 ||
        total != (size_t)w * h * 4 || total > 64ULL * 1024 * 1024)
        return;

    m_shotReceiving  = true;
    m_shotV2         = false;
    m_shotFrameId    = fid;
    m_shotWidth      = w;
    m_shotHeight     = h;
    m_shotExpected   = total;
    m_shotReceived   = 0;
    m_shotChunkCount = chunks;
    m_shotImage.fill(0, (int)total);
    m_shotChunkSeen.fill(false, chunks);
    setStatus(QString("[shot] receiving frame %1 %2x%3").arg(fid).arg(w).arg(h));
}

void MainWindow::appendShotChunk(const QByteArray& rest)
{
    if (!m_shotReceiving) return;
    // frameId|idx|offsetHex|lenHex|dataHex
    int p1 = rest.indexOf('|');
    int p2 = rest.indexOf('|', p1+1);
    int p3 = rest.indexOf('|', p2+1);
    int p4 = rest.indexOf('|', p3+1);
    if (p4 < 0) return;

    uint fid = rest.left(p1).toUInt();
    uint idx = rest.mid(p1+1, p2-p1-1).toUInt();
    quint64 off = rest.mid(p2+1, p3-p2-1).toULongLong(nullptr, 16);
    uint len = rest.mid(p3+1, p4-p3-1).toUInt(nullptr, 16);
    QByteArray hex = rest.mid(p4+1);

    if (fid != m_shotFrameId || idx >= m_shotChunkCount) return;
    if ((qint64)(off + len) > m_shotImage.size()) return;
    if ((int)(len * 2) > hex.size()) return;
    if (m_shotChunkSeen[idx]) return;

    QByteArray bin = QByteArray::fromHex(hex.left(len * 2));
    memcpy(m_shotImage.data() + off, bin.constData(), bin.size());
    m_shotChunkSeen[idx] = true;
    m_shotReceived += len;
}

void MainWindow::endShotFrame(const QByteArray& rest)
{
    if (!m_shotReceiving) return;
    int p = rest.indexOf('|');
    uint fid = rest.left(p > 0 ? p : rest.size()).toUInt();
    if (fid != m_shotFrameId) return;
    m_shotReceiving = false;

    if (m_shotV2) {
        /* V2: decompress RLE, apply XOR diff */
        shotLog("END fid=%u compRecv=%zu/%zu isKey=%d prevSz=%d expected=%zu",
                fid, m_shotCompRecv, m_shotCompSize, m_shotIsKey,
                m_shotPrevImage.size(), m_shotExpected);
        if (m_shotCompRecv != m_shotCompSize) {
            setStatus(QString("[shot2] frame %1 incomplete comp %2/%3")
                      .arg(fid).arg(m_shotCompRecv).arg(m_shotCompSize));
            m_shotPrevImage.clear();                   /* desync: drop prev to avoid garbage propagation */
            m_tcp->sendCommand(NETDRV_CMD_SHOT_KEYFRAME); /* ask driver for keyframe */
            if (m_shotLive) m_shotTimer->start(33);
            return;
        }

        quint32 dwordCount = (quint32)(m_shotExpected / 4);
        QByteArray decoded;

        /* When driver's RLE failed it sends raw pixels with comp==raw and
           isKey=1.  Detect this and skip RLE decode — the raw pixel bytes
           would be mis-interpreted as RLE runs (the clamping logic inside
           rleDecompress almost always "succeeds" on random data, producing
           garbage of the correct size). */
        if (m_shotIsKey && m_shotCompSize == m_shotExpected) {
            decoded = m_shotCompBuf;
        } else {
            decoded = rleDecompress(m_shotCompBuf, dwordCount);
        }

        if (decoded.size() != (int)m_shotExpected) {
            /* RLE decode size mismatch — treat as raw keyframe data */
            if (m_shotCompBuf.size() == (int)m_shotExpected) {
                decoded = m_shotCompBuf;
                m_shotIsKey = true;
            } else {
                setStatus(QString("[shot2] frame %1 decode error %2 != %3")
                          .arg(fid).arg(decoded.size()).arg(m_shotExpected));
                m_shotPrevImage.clear();
                m_tcp->sendCommand(NETDRV_CMD_SHOT_KEYFRAME);
                if (m_shotLive) m_shotTimer->start(33);
                return;
            }
        }

        if (m_shotIsKey) {
            m_shotImage = decoded;
        } else {
            /* XOR with previous frame */
            if (m_shotPrevImage.size() == (int)m_shotExpected) {
                const quint32* diff = (const quint32*)decoded.constData();
                const quint32* prev = (const quint32*)m_shotPrevImage.constData();
                quint32* out = (quint32*)m_shotImage.data();
                for (quint32 i = 0; i < dwordCount; i++)
                    out[i] = prev[i] ^ diff[i];
            } else {
                /* No valid prev — cannot apply diff, wait for keyframe */
                setStatus(QString("[shot2] frame %1 waiting for keyframe (no prev)")
                          .arg(fid));
                m_tcp->sendCommand(NETDRV_CMD_SHOT_KEYFRAME);
                if (m_shotLive) m_shotTimer->start(33);
                return;
            }
        }
        m_shotPrevImage = m_shotImage;

        renderShot();
        setStatus(QString("[shot2] frame %1 %2x%3 comp=%4/%5 key=%6")
                  .arg(fid).arg(m_shotWidth).arg(m_shotHeight)
                  .arg(m_shotCompSize).arg(m_shotExpected).arg(m_shotIsKey));
    } else {
        /* V1: hex-based, data already in m_shotImage */
        if (m_shotReceived != m_shotExpected) {
            setStatus(QString("[shot] frame %1 incomplete %2/%3")
                      .arg(fid).arg(m_shotReceived).arg(m_shotExpected));
            if (m_shotLive) m_shotTimer->start(33);
            return;
        }

        renderShot();
        setStatus(QString("[shot] frame %1 %2x%3 rendered (%4 bytes)")
                  .arg(fid).arg(m_shotWidth).arg(m_shotHeight).arg(m_shotExpected));
    }

    if (m_shotLive && currentTab() == 3)
        m_shotTimer->start(50);  /* ~20 fps cap; gives other TCP ops breathing room */
}

void MainWindow::renderShot()
{
    if (m_shotImage.isEmpty() || m_shotWidth == 0 || m_shotHeight == 0) return;

    // BGRA data -> QImage (Format_ARGB32 = BGRA in memory on little-endian)
    QImage img((const uchar*)m_shotImage.constData(),
               m_shotWidth, m_shotHeight, m_shotWidth * 4,
               QImage::Format_ARGB32);

    QPixmap pm = QPixmap::fromImage(img).scaled(
        m_shotLabel->size(), Qt::KeepAspectRatio, Qt::SmoothTransformation);
    m_shotLabel->setPixmap(pm);
}

// ---- V2 binary shot chunk ----

void MainWindow::appendShotChunkV2(const QByteArray& binPayload)
{
    if (!m_shotReceiving || !m_shotV2) return;
    // binPayload: "Z|" + fid(4B LE) + idx(4B LE) + off(4B LE) + len(4B LE) + data
    if (binPayload.size() < 18) return;
    const uchar* p = (const uchar*)binPayload.constData() + 2;
    quint32 fid = *(const quint32*)p;  p += 4;
    quint32 idx = *(const quint32*)p;  p += 4;
    quint32 off = *(const quint32*)p;  p += 4;
    quint32 len = *(const quint32*)p;  p += 4;

    if (fid != m_shotFrameId || idx >= m_shotChunkCount) return;
    if ((qint64)(off + len) > m_shotCompBuf.size()) return;
    if ((int)(18 + len) > binPayload.size()) return;
    if (m_shotChunkSeen[idx]) return;

    memcpy(m_shotCompBuf.data() + off, p, len);
    m_shotChunkSeen[idx] = true;
    m_shotCompRecv += len;
    if (idx == 0 || m_shotCompRecv == m_shotCompSize)
        shotLog("  CHUNK fid=%u idx=%u/%u off=%u len=%u compRecv=%zu/%zu",
                fid, idx, m_shotChunkCount, off, len, m_shotCompRecv, m_shotCompSize);
}

QByteArray MainWindow::rleDecompress(const QByteArray& comp, quint32 dwordCount)
{
    QByteArray out(dwordCount * 4, Qt::Uninitialized);
    quint32* dst = (quint32*)out.data();
    const uchar* src = (const uchar*)comp.constData();
    int srcLen = comp.size();
    int pos = 0;
    quint32 written = 0;

    while (pos + 6 <= srcLen && written < dwordCount) {
        quint16 count = *(const quint16*)(src + pos);
        quint32 value = *(const quint32*)(src + pos + 2);
        pos += 6;
        if (written + count > dwordCount)
            count = (quint16)(dwordCount - written);
        for (quint16 i = 0; i < count; i++)
            dst[written++] = value;
    }

    if (written < dwordCount)
        out.resize(written * 4);
    return out;
}

// ---- file browser ----

void MainWindow::initFileTree()
{
#ifdef Q_OS_WIN
    WCHAR drives[256] = {};
    DWORD n = GetLogicalDriveStringsW(255, drives);
    for (LPWSTR d = drives; *d; d += wcslen(d) + 1) {
        QString driveText = QString::fromWCharArray(d); // "C:\"
        auto* item = new QTreeWidgetItem(m_fileTree, {driveText});
        item->setChildIndicatorPolicy(QTreeWidgetItem::ShowIndicator);
        m_treeIndex[driveText] = item;
    }
#else
    auto* root = new QTreeWidgetItem(m_fileTree, {"/"});
    root->setChildIndicatorPolicy(QTreeWidgetItem::ShowIndicator);
    m_treeIndex["/"] = root;
#endif
}

void MainWindow::requestFileEnum(const QString& path)
{
    QByteArray cmd = QByteArray(NETDRV_CMD_ENUM_FILE) + path.toUtf8() + "\n";
    m_tcp->sendCommand(cmd);
    setStatus(QString("[file] requesting %1").arg(path));
}

void MainWindow::beginFileBatch(const QString& path)
{
    m_filePending = path;
    m_fileIncoming.clear();
}

void MainWindow::appendFileEntry(bool isDir, quint64 size, const QString& name)
{
    if (m_filePending.isEmpty() || name.isEmpty()) return;
    m_fileIncoming.append({isDir, size, name});
}

void MainWindow::endFileBatch(const QString& path)
{
    auto it = m_treeIndex.find(path);
    if (it == m_treeIndex.end()) {
        m_filePending.clear();
        m_fileIncoming.clear();
        return;
    }
    QTreeWidgetItem* dir = it.value();

    // clear children
    while (dir->childCount()) delete dir->takeChild(0);

    // insert directory children with dummy for expand arrow
    for (const auto& e : m_fileIncoming) {
        if (!e.isDir) continue;
        auto* child = new QTreeWidgetItem(dir, {e.name});
        child->setChildIndicatorPolicy(
            QTreeWidgetItem::ShowIndicator);
        QString childPath = path.endsWith('\\')
            ? path + e.name : path + '\\' + e.name;
        m_treeIndex[childPath] = child;
    }

    m_fileEntries[dir] = m_fileIncoming;
    m_fileLoaded.insert(dir);
    m_fileIncoming.clear();
    m_filePending.clear();

    if (m_fileTree->selectedItems().contains(dir))
        populateFileList(dir);

    setStatus(QString("[file] %1: %2 entries").arg(path).arg(m_fileEntries[dir].size()));
}

void MainWindow::populateFileList(QTreeWidgetItem* item)
{
    m_fileList->setRowCount(0);
    auto it = m_fileEntries.find(item);
    if (it == m_fileEntries.end()) return;

    for (const auto& e : it.value()) {
        int row = m_fileList->rowCount();
        m_fileList->insertRow(row);
        m_fileList->setItem(row, 0, new QTableWidgetItem(e.name));
        if (e.isDir) {
            m_fileList->setItem(row, 1, new QTableWidgetItem(""));
            m_fileList->setItem(row, 2, new QTableWidgetItem("<DIR>"));
        } else {
            QString sz;
            if (e.size < 1024) sz = QString("%1 B").arg(e.size);
            else if (e.size < 1024*1024) sz = QString("%1 KB").arg(e.size/1024.0, 0, 'f', 1);
            else if (e.size < 1024ULL*1024*1024) sz = QString("%1 MB").arg(e.size/(1024.0*1024), 0, 'f', 2);
            else sz = QString("%1 GB").arg(e.size/(1024.0*1024*1024), 0, 'f', 2);
            m_fileList->setItem(row, 1, new QTableWidgetItem(sz));
            m_fileList->setItem(row, 2, new QTableWidgetItem("File"));
        }
    }
}

QString MainWindow::treePath(QTreeWidgetItem* item) const
{
    if (!item) return {};
    QString name = item->text(0);
    QTreeWidgetItem* parent = item->parent();
    if (!parent) return name;
    QString pp = treePath(parent);
    return pp.endsWith('\\') ? pp + name : pp + '\\' + name;
}

void MainWindow::onTreeExpanded(QTreeWidgetItem* item)
{
    if (m_fileLoaded.contains(item)) return;
    requestFileEnum(treePath(item));
}

void MainWindow::onTreeSelected()
{
    auto sel = m_fileTree->selectedItems();
    if (sel.isEmpty()) { m_fileList->setRowCount(0); return; }
    QTreeWidgetItem* item = sel.first();
    if (!m_fileLoaded.contains(item)) {
        m_fileList->setRowCount(0);
        requestFileEnum(treePath(item));
        return;
    }
    populateFileList(item);
}

// ---- download ----

void MainWindow::onDownload()
{
    if (currentTab() != 2) { setStatus("[file] switch to File tab first"); return; }
    int row = m_fileList->currentRow();
    if (row < 0) { setStatus("[get] select a file first"); return; }
    auto* typeItem = m_fileList->item(row, 2);
    if (typeItem && typeItem->text() == "<DIR>") { setStatus("[get] cannot download directory"); return; }

    QString name = m_fileList->item(row, 0)->text();
    auto selTree = m_fileTree->selectedItems();
    if (selTree.isEmpty()) { setStatus("[get] select parent directory"); return; }
    QString remotePath = treePath(selTree.first());
    if (!remotePath.endsWith('\\')) remotePath += '\\';
    remotePath += name;

    m_dlLocalPath = QFileDialog::getSaveFileName(this, "Save As", name);
    if (m_dlLocalPath.isEmpty()) return;

    if (m_dlFile) { m_dlFile->close(); delete m_dlFile; m_dlFile = nullptr; }

    m_dlRemotePath = remotePath;
    m_dlReceived = 0;
    m_dlTotal = 0;
    m_dlRetries = 0;

    // Show download progress
    m_progressBar->setRange(0, 100);
    m_progressBar->setValue(0);
    m_progressBar->setTextVisible(false);
    m_progressBar->show();
    m_progressLabel->setText(QString("Download: %1").arg(name));
    m_progressLabel->show();

    QByteArray cmd = QByteArray(NETDRV_CMD_GET_FILE) + remotePath.toUtf8() + "\n";
    m_tcp->sendCommand(cmd);
    setStatus(QString("[get] requested %1").arg(remotePath));
}

void MainWindow::beginDownload(quint64 total)
{
    if (m_dlLocalPath.isEmpty()) return;
    if (m_dlFile) { m_dlFile->close(); delete m_dlFile; }
    m_dlFile = new QFile(m_dlLocalPath, this);
    if (!m_dlFile->open(QIODevice::WriteOnly)) {
        setStatus(QString("[get] cannot create %1").arg(m_dlLocalPath));
        delete m_dlFile; m_dlFile = nullptr;
        return;
    }
    m_dlTotal = total;
    m_dlReceived = 0;
    setStatus(QString("[get] receiving %1 bytes -> %2").arg(total).arg(m_dlLocalPath));
}

void MainWindow::appendDownloadChunk(quint64 off, const QByteArray& data)
{
    if (!m_dlFile || !m_dlFile->isOpen() || data.isEmpty()) return;
    m_dlFile->seek(off);
    m_dlFile->write(data);
    m_dlReceived += data.size();
    if (m_dlTotal > 0 && m_progressBar->isVisible()) {
        int pct = (int)(m_dlReceived * 100 / m_dlTotal);
        m_progressBar->setValue(pct);
        m_progressLabel->setText(QString("Download: %1%%  %2/%3")
            .arg(pct).arg(m_dlReceived).arg(m_dlTotal));
    }
}

void MainWindow::endDownload(quint64 reported)
{
    if (!m_dlFile) return;
    m_dlFile->close();
    delete m_dlFile;
    m_dlFile = nullptr;

    if (m_dlReceived < reported && m_dlRetries < 3 && !m_dlRemotePath.isEmpty()) {
        ++m_dlRetries;
        setStatus(QString("[get] incomplete %1/%2, retry %3/3")
                  .arg(m_dlReceived).arg(reported).arg(m_dlRetries));
        m_dlReceived = 0;
        m_dlTotal = 0;
        QByteArray cmd = QByteArray(NETDRV_CMD_GET_FILE) + m_dlRemotePath.toUtf8() + "\n";
        m_tcp->sendCommand(cmd);
        return;
    }

    if (m_dlReceived == reported)
        setStatus(QString("[get] done %1 bytes -> %2").arg(m_dlReceived).arg(m_dlLocalPath));
    else
        setStatus(QString("[get] INCOMPLETE %1/%2 -> %3")
                  .arg(m_dlReceived).arg(reported).arg(m_dlLocalPath));
    m_dlRetries = 0;
    m_progressBar->hide();
    m_progressLabel->hide();
}

// ---- upload ----

void MainWindow::onUpload()
{
    if (currentTab() != 2) { setStatus("[file] switch to File tab first"); return; }
    if (m_ulActive) { setStatus("[put] upload already running"); return; }
    auto selTree = m_fileTree->selectedItems();
    if (selTree.isEmpty()) { setStatus("[put] select target directory"); return; }
    QString remoteDir = treePath(selTree.first());

    QString localPath = QFileDialog::getOpenFileName(this, "Select File to Upload");
    if (localPath.isEmpty()) return;

    resetUpload();
    m_ulFile = new QFile(localPath, this);
    if (!m_ulFile->open(QIODevice::ReadOnly)) {
        setStatus("[put] cannot open source");
        resetUpload();
        return;
    }

    quint64 total = m_ulFile->size();
    if (total > 64ULL * 1024 * 1024) {
        setStatus("[put] file too large (>64MB)");
        resetUpload();
        return;
    }

    m_ulFileName = QFileInfo(localPath).fileName();
    m_ulRemotePath = remoteDir.endsWith('\\')
        ? remoteDir + m_ulFileName : remoteDir + '\\' + m_ulFileName;
    m_ulTotal = total;
    m_ulSent = 0;
    m_ulChunkSize = 8192;
    m_ulChunkCount = (uint)((total + m_ulChunkSize - 1) / m_ulChunkSize);
    if (m_ulChunkCount == 0) m_ulChunkCount = 1;
    m_ulIndex = 0;
    m_ulActive = true;

    QByteArray putCmd = QByteArray(NETDRV_CMD_PUT_BEGIN) + m_ulRemotePath.toUtf8()
        + "|" + QByteArray::number(total, 16).toUpper()
        + "|" + QByteArray::number(m_ulChunkSize)
        + "|" + QByteArray::number(m_ulChunkCount) + "\n";
    if (!m_tcp->sendCommand(putCmd)) {
        setStatus("[put] cannot send begin command");
        resetUpload();
        return;
    }

    m_progressBar->setRange(0, (int)m_ulChunkCount);
    m_progressBar->setValue(0);
    m_progressBar->setTextVisible(false);
    m_progressBar->show();
    m_progressLabel->setText(QString("Upload: %1  0/%2").arg(m_ulFileName).arg(total));
    m_progressLabel->show();

    m_uploadTimer->start();
    setStatus(QString("[put] started %1 -> %2").arg(localPath).arg(m_ulRemotePath));
}

void MainWindow::pumpUpload()
{
    if (!m_ulActive || !m_ulFile)
        return;

    if (!m_tcp->isDriverConnected()) {
        setStatus("[put] driver disconnected");
        resetUpload();
        return;
    }

    static const char kHex[] = "0123456789ABCDEF";
    const int maxChunksPerTick = 8;
    int chunksThisTick = 0;

    while (m_ulSent < m_ulTotal && chunksThisTick < maxChunksPerTick) {
        if (m_tcp->fileBytesToWrite() > NETDRV_TCP_FILE_WRITE_WATERMARK)
            break;

        QByteArray chunk = m_ulFile->read(m_ulChunkSize);
        if (chunk.isEmpty()) break;

        QByteArray hex;
        hex.reserve(chunk.size() * 2);
        for (unsigned char b : chunk) {
            hex.append(kHex[(b >> 4) & 0xF]);
            hex.append(kHex[b & 0xF]);
        }

        QByteArray pkt = "P|" + QByteArray::number(m_ulIndex)
            + "|" + QByteArray::number(m_ulSent, 16).toUpper()
            + "|" + QByteArray::number(chunk.size(), 16).toUpper()
            + "|" + hex + "\n";
        if (!m_tcp->sendCommand(pkt)) {
            setStatus("[put] send failed");
            resetUpload();
            return;
        }

        m_ulSent += chunk.size();
        ++m_ulIndex;
        ++chunksThisTick;

        if ((m_ulIndex & 0xF) == 0 || m_ulSent == m_ulTotal) {
            m_progressBar->setValue((int)m_ulIndex);
            m_progressLabel->setText(QString("Upload: %1%%  %2/%3")
                .arg((int)(m_ulSent * 100 / m_ulTotal)).arg(m_ulSent).arg(m_ulTotal));
            setStatus(QString("[put] %1 / %2").arg(m_ulSent).arg(m_ulTotal));
        }
    }

    if (m_ulSent >= m_ulTotal) {
        finishUpload();
        return;
    }

    if (!m_uploadTimer->isActive())
        m_uploadTimer->start();
}

void MainWindow::finishUpload()
{
    if (!m_ulActive)
        return;

    if (m_ulFile) {
        m_ulFile->close();
    }

    QByteArray endCmd = QByteArray(NETDRV_CMD_PUT_END) + m_ulRemotePath.toUtf8()
        + "|" + QByteArray::number(m_ulTotal, 16).toUpper() + "\n";
    if (!m_tcp->sendCommand(endCmd)) {
        setStatus("[put] cannot send end command");
        resetUpload();
        return;
    }
    m_progressBar->setValue(m_progressBar->maximum());
    m_progressLabel->setText("Upload: 100% Complete");
    QTimer::singleShot(1000, this, [this]{
        m_progressBar->hide();
        m_progressLabel->hide();
    });
    setStatus(QString("[put] sent %1 bytes (%2 chunks) -> %3")
              .arg(m_ulSent).arg(m_ulIndex).arg(m_ulRemotePath));
    resetUpload();
}

void MainWindow::resetUpload()
{
    if (m_uploadTimer)
        m_uploadTimer->stop();
    if (m_ulFile) {
        m_ulFile->close();
        delete m_ulFile;
        m_ulFile = nullptr;
    }
    m_ulRemotePath.clear();
    m_ulFileName.clear();
    m_ulTotal = 0;
    m_ulSent = 0;
    m_ulChunkSize = 8192;
    m_ulChunkCount = 0;
    m_ulIndex = 0;
    m_ulActive = false;
}
