// TcpChannel.h --- 单条 TCP 通道(继承 NetLinkBase)。
//
// 兼容点:类名、信号(authenticated/disconnected/packetReceived/bytesWritten)、
// 公共方法(startServer/isConnected/peerAddress/peerPort/bytesToWrite/sendFrame)
// 与重构前完全一致,TcpLink 与 MainWindow 无需修改使用方式。
//
#pragma once

#include "NetLinkBase.h"

#include <QTcpServer>
#include <QTcpSocket>
#include <QByteArray>

class TcpChannel : public NetLinkBase
{
    Q_OBJECT
public:
    TcpChannel(int channelId, const QString& name, QObject* parent = nullptr);

    // ---- 兼容旧 API ----
    bool    startServer(const QString& bindIp, quint16 port);
    bool    isConnected() const;        // 同 NetLinkBase::isConnected,但额外检查 authenticated
    QString peerAddress() const;
    quint16 peerPort()    const;
    qint64  bytesToWrite() const;
    bool    sendFrame(const QByteArray& payload);

    // ---- 6 契约虚函数 ----
    bool       doConnect(const QString& bindIp, quint16 port) override;
    int        recvPacket(QByteArray& inout, QByteArray& outPayload) override;
    bool       verifyPacket(const QByteArray& bytes) const override;
    QByteArray buildPacket(const QByteArray& payload) const override;

signals:
    void authenticated(int channelId, const QString& ip, quint16 port);
    void disconnected(int channelId);
    void packetReceived(int channelId, const QByteArray& payload);
    void bytesWritten(int channelId, qint64 bytes);

protected:
    bool sendRaw(const QByteArray& bytes) override;

private slots:
    void onNewConnection();
    void onReadyRead();
    void onSocketDisconnected();
    void onBytesWritten(qint64 bytes);

private:
    void processBuffer();
    void sendAuthAck(bool ok);

    int         m_channelId = 0;
    QTcpServer* m_server = nullptr;
    QTcpSocket* m_client = nullptr;
    QByteArray  m_readBuf;
    bool        m_authenticated = false;
};
