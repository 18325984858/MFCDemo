// TcpChannel.cpp --- 单条 TCP 通道实现(继承 NetLinkBase)。
#include "TcpChannel.h"
#include "../Shared/Protocol.h"
#include "../Shared/NdarkLog.h"

#include <QHostAddress>
#include <QDebug>
#include <cstring>

static constexpr quint32 kFrameMagic   = NETDRV_TCP_FRAME_MAGIC;
static constexpr int     kFrameHdrSize = NETDRV_TCP_FRAME_HDR_SIZE;
static constexpr quint32 kMaxFrame     = NETDRV_TCP_MAX_FRAME_SIZE;

TcpChannel::TcpChannel(int channelId, const QString& name, QObject* parent)
    : NetLinkBase(name, parent), m_channelId(channelId)
{
}

// ============================================================
// 6 契约方法实现
// ============================================================

bool TcpChannel::doConnect(const QString& bindIp, quint16 port)
{
    if (m_server) return true;
    m_server = new QTcpServer(this);
    connect(m_server, &QTcpServer::newConnection,
            this, &TcpChannel::onNewConnection);

    QHostAddress addr = bindIp.isEmpty() ? QHostAddress::AnyIPv4
                                         : QHostAddress(bindIp);
    if (!m_server->listen(addr, port)) {
        NDARK_LOG_ERR("tcp[%s] listen %s:%u failed: %s",
                      qPrintable(linkName()), qPrintable(bindIp), port,
                      qPrintable(m_server->errorString()));
        qWarning() << "TCP" << linkName() << "listen failed on" << port
                   << ":" << m_server->errorString();
        delete m_server;
        m_server = nullptr;
        return false;
    }
    NDARK_LOG_INFO("tcp[%s] listening on %s:%u",
                   qPrintable(linkName()), qPrintable(bindIp), port);
    return true;
}

bool TcpChannel::verifyPacket(const QByteArray& bytes) const
{
    if (bytes.size() < kFrameHdrSize) return false;
    quint32 magic  = 0;
    quint32 payLen = 0;
    memcpy(&magic,  bytes.constData(),     sizeof(magic));
    memcpy(&payLen, bytes.constData() + 4, sizeof(payLen));
    return magic == kFrameMagic && payLen <= kMaxFrame;
}

QByteArray TcpChannel::buildPacket(const QByteArray& payload) const
{
    QByteArray out;
    out.resize(kFrameHdrSize + payload.size());
    quint32 magic = kFrameMagic;
    quint32 size  = static_cast<quint32>(payload.size());
    memcpy(out.data(),     &magic, sizeof(magic));
    memcpy(out.data() + 4, &size,  sizeof(size));
    if (!payload.isEmpty())
        memcpy(out.data() + kFrameHdrSize, payload.constData(), payload.size());
    return out;
}

int TcpChannel::recvPacket(QByteArray& inout, QByteArray& outPayload)
{
    if (inout.size() < kFrameHdrSize) return 0;
    if (!verifyPacket(inout))         return -1;
    quint32 payLen = 0;
    memcpy(&payLen, inout.constData() + 4, sizeof(payLen));
    const int total = kFrameHdrSize + int(payLen);
    if (inout.size() < total) return 0;
    outPayload = inout.mid(kFrameHdrSize, int(payLen));
    inout.remove(0, total);
    return total;
}

bool TcpChannel::sendRaw(const QByteArray& bytes)
{
    if (!m_client) return false;
    qint64 n = m_client->write(bytes);
    return n == bytes.size();
}

// ============================================================
// 兼容旧 API
// ============================================================

bool TcpChannel::startServer(const QString& bindIp, quint16 port)
{
    return doConnect(bindIp, port);
}

bool TcpChannel::isConnected() const
{
    return m_client && m_client->state() == QAbstractSocket::ConnectedState
           && m_authenticated;
}

QString TcpChannel::peerAddress() const
{
    return m_client ? m_client->peerAddress().toString() : QString{};
}

quint16 TcpChannel::peerPort() const
{
    return m_client ? m_client->peerPort() : quint16(0);
}

qint64 TcpChannel::bytesToWrite() const
{
    return m_client ? m_client->bytesToWrite() : qint64(0);
}

bool TcpChannel::sendFrame(const QByteArray& payload)
{
    if (!m_client || !m_authenticated) return false;
    return sendRaw(buildPacket(payload));
}

// ============================================================
// 内部槽 & 状态机
// ============================================================

void TcpChannel::onNewConnection()
{
    QTcpSocket* pending = m_server->nextPendingConnection();
    if (!pending) return;

    if (m_client) {
        // 只允许一个活动连接;后续连接拒绝。
        NDARK_LOG_WARN("tcp[%s] reject duplicate connection from %s:%u",
                       qPrintable(linkName()),
                       qPrintable(pending->peerAddress().toString()),
                       pending->peerPort());
        pending->close();
        pending->deleteLater();
        return;
    }

    m_client = pending;
    m_authenticated = false;
    m_readBuf.clear();
    NDARK_LOG_INFO("tcp[%s] accepted connection from %s:%u",
                   qPrintable(linkName()),
                   qPrintable(m_client->peerAddress().toString()),
                   m_client->peerPort());

    connect(m_client, &QTcpSocket::readyRead,
            this, &TcpChannel::onReadyRead);
    connect(m_client, &QTcpSocket::disconnected,
            this, &TcpChannel::onSocketDisconnected);
    connect(m_client, &QTcpSocket::bytesWritten,
            this, &TcpChannel::onBytesWritten);
}

void TcpChannel::onReadyRead()
{
    if (!m_client) return;
    m_readBuf.append(m_client->readAll());
    processBuffer();
}

void TcpChannel::onSocketDisconnected()
{
    m_authenticated = false;
    setConnected(false);
    NDARK_LOG_INFO("tcp[%s] socket disconnected", qPrintable(linkName()));
    if (m_client) {
        m_client->deleteLater();
        m_client = nullptr;
    }
    m_readBuf.clear();
    emit disconnected(m_channelId);
}

void TcpChannel::onBytesWritten(qint64 bytes)
{
    emit bytesWritten(m_channelId, bytes);
}

void TcpChannel::processBuffer()
{
    while (true) {
        QByteArray payload;
        int n = recvPacket(m_readBuf, payload);
        if (n == 0)  return;                            // 不完整,等更多
        if (n < 0) {                                    // 帧错,断开
            if (m_client) m_client->disconnectFromHost();
            return;
        }

        touchRx();

        if (!m_authenticated) {
            // 首帧必须是 AUTH_KEY
            if (payload.size() == NETDRV_TCP_AUTH_KEY_LEN &&
                memcmp(payload.constData(), NETDRV_TCP_AUTH_KEY,
                       NETDRV_TCP_AUTH_KEY_LEN) == 0)
            {
                m_authenticated = true;
                setConnected(true);
                sendAuthAck(true);
                NDARK_LOG_INFO("tcp[%s] auth ok", qPrintable(linkName()));
                emit authenticated(m_channelId, peerAddress(), peerPort());
            } else {
                NDARK_LOG_WARN("tcp[%s] auth FAILED (got %d bytes)",
                               qPrintable(linkName()), int(payload.size()));
                sendAuthAck(false);
                if (m_client) m_client->disconnectFromHost();
            }
            continue;
        }

        emit packetReceived(m_channelId, payload);
    }
}

void TcpChannel::sendAuthAck(bool ok)
{
    QByteArray ack(1, ok ? '1' : '0');
    QByteArray frame = buildPacket(ack);
    if (m_client) {
        m_client->write(frame);
        m_client->flush();
    }
}
