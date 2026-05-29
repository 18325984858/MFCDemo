// TcpLink.h --- 聚合三条 TcpChannel(control/screen/file)的容器。
//
// 说明:TcpLink 本身不继承 NetLinkBase —— 它是"链路集合"而非"单条链路"。
// 每条物理通道(TcpChannel)才是 NetLinkBase 的具体实现。
//
#pragma once

#include <QObject>
#include <QByteArray>
#include "TcpChannel.h"

class TcpLink : public QObject
{
    Q_OBJECT
public:
    explicit TcpLink(QObject* parent = nullptr);

    bool    startServer(const QString& bindIp, quint16 port);
    bool    sendFrame(const QByteArray& payload);
    bool    sendCommand(const QByteArray& command);
    bool    sendFrameTo(int channelId, const QByteArray& payload);
    bool    isDriverConnected() const;
    bool    isScreenConnected() const;
    bool    isFileConnected()   const;
    QString driverAddr() const;
    qint64  fileBytesToWrite() const;

signals:
    void driverConnected(const QString& ip, quint16 port);
    void driverDisconnected();
    void packetReceived(const QByteArray& payload);
    void fileBytesWritten(qint64 bytes);

private slots:
    void onChannelAuthenticated(int channelId, const QString& ip, quint16 port);
    void onChannelDisconnected(int channelId);
    void onChannelPacket(int channelId, const QByteArray& payload);
    void onChannelBytesWritten(int channelId, qint64 bytes);

private:
    TcpChannel* channelById(int channelId) const;

    TcpChannel* m_control = nullptr;
    TcpChannel* m_screen  = nullptr;
    TcpChannel* m_file    = nullptr;
};
