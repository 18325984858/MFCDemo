// TcpLink.cpp --- 聚合三条 TcpChannel 的容器实现。
#include "TcpLink.h"
#include "../Shared/Protocol.h"
#include "../Shared/ProtocolRoute.h"
#include "../Shared/NdarkLog.h"

TcpLink::TcpLink(QObject* parent) : QObject(parent)
{
    m_control = new TcpChannel(NETDRV_TCP_CHANNEL_CONTROL, "tcp-control", this);
    m_screen  = new TcpChannel(NETDRV_TCP_CHANNEL_SCREEN,  "tcp-screen",  this);
    m_file    = new TcpChannel(NETDRV_TCP_CHANNEL_FILE,    "tcp-file",    this);

    for (TcpChannel* channel : {m_control, m_screen, m_file}) {
        connect(channel, &TcpChannel::authenticated,
                this, &TcpLink::onChannelAuthenticated);
        connect(channel, &TcpChannel::disconnected,
                this, &TcpLink::onChannelDisconnected);
        connect(channel, &TcpChannel::packetReceived,
                this, &TcpLink::onChannelPacket);
        connect(channel, &TcpChannel::bytesWritten,
                this, &TcpLink::onChannelBytesWritten);
    }
}

bool TcpLink::startServer(const QString& bindIp, quint16 port)
{
    bool ok = true;
    ok = m_control->startServer(bindIp, port)                       && ok;
    ok = m_screen->startServer(bindIp, NETDRV_TCP_SCREEN_PORT)      && ok;
    ok = m_file->startServer(bindIp,   NETDRV_TCP_FILE_PORT)        && ok;
    NDARK_LOG_INFO("TcpLink startServer bindIp=%s control=%u screen=%u file=%u ok=%d",
                   qPrintable(bindIp), port,
                   NETDRV_TCP_SCREEN_PORT, NETDRV_TCP_FILE_PORT, ok ? 1 : 0);
    return ok;
}

bool TcpLink::isDriverConnected() const { return m_control && m_control->isConnected(); }
bool TcpLink::isScreenConnected() const { return m_screen  && m_screen->isConnected(); }
bool TcpLink::isFileConnected()   const { return m_file    && m_file->isConnected(); }

QString TcpLink::driverAddr() const
{
    return m_control ? m_control->peerAddress() : QString{};
}

qint64 TcpLink::fileBytesToWrite() const
{
    return m_file ? m_file->bytesToWrite() : qint64(0);
}

bool TcpLink::sendFrame(const QByteArray& payload)
{
    return sendFrameTo(NETDRV_TCP_CHANNEL_CONTROL, payload);
}

bool TcpLink::sendCommand(const QByteArray& command)
{
    int channelId = NetDrvClassifyAppCommand(command.constData(),
                                             (unsigned long)command.size());
    if (sendFrameTo(channelId, command)) return true;
    if (channelId != NETDRV_TCP_CHANNEL_CONTROL)
        return sendFrameTo(NETDRV_TCP_CHANNEL_CONTROL, command);
    return false;
}

bool TcpLink::sendFrameTo(int channelId, const QByteArray& payload)
{
    TcpChannel* channel = channelById(channelId);
    return channel && channel->sendFrame(payload);
}

TcpChannel* TcpLink::channelById(int channelId) const
{
    switch (channelId) {
    case NETDRV_TCP_CHANNEL_SCREEN:  return m_screen;
    case NETDRV_TCP_CHANNEL_FILE:    return m_file;
    case NETDRV_TCP_CHANNEL_CONTROL:
    default:                         return m_control;
    }
}

void TcpLink::onChannelAuthenticated(int channelId, const QString& ip, quint16 port)
{
    Q_UNUSED(channelId);
    Q_UNUSED(ip);
    Q_UNUSED(port);
}

void TcpLink::onChannelDisconnected(int channelId)
{
    if (channelId == NETDRV_TCP_CHANNEL_CONTROL) {
        NDARK_LOG_WARN("control channel down -> driverDisconnected");
        emit driverDisconnected();
    }
}

void TcpLink::onChannelPacket(int channelId, const QByteArray& payload)
{
    if (payload.size() >= 2 && payload[0] == 'R' && payload[1] == '|') {
        if (payload.startsWith("R|hello") && channelId == NETDRV_TCP_CHANNEL_CONTROL) {
            NDARK_LOG_INFO("tcp driver hello from %s:%u",
                           qPrintable(m_control->peerAddress()),
                           m_control->peerPort());
            emit driverConnected(m_control->peerAddress(), m_control->peerPort());
        }
        return;
    }
    emit packetReceived(payload);
}

void TcpLink::onChannelBytesWritten(int channelId, qint64 bytes)
{
    if (channelId == NETDRV_TCP_CHANNEL_FILE)
        emit fileBytesWritten(bytes);
}
