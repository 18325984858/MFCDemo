// UdpLink.h --- UDP 实现,继承自 NetLinkBase。
//
// 兼容点:对外 API(start / sendCommand / enqueue / 信号 packetReceived /
// driverConnected / isDriverConnected / driverAddr / driverPort / queueSize)
// 与重构前一致,MainWindow 无需任何修改。
//
#pragma once

#include "NetLinkBase.h"

#include <QUdpSocket>
#include <QHostAddress>
#include <QQueue>
#include <QTimer>

class UdpLink : public NetLinkBase
{
    Q_OBJECT
public:
    explicit UdpLink(QObject* parent = nullptr);

    // ---- 兼容旧 API ----
    bool    start(const QString& bindIp, quint16 port);
    void    enqueue(const QByteArray& command);
    bool    sendCommand(const QByteArray& command);
    bool    isDriverConnected() const { return isConnected(); }
    QString driverAddr() const        { return m_driverIp.toString(); }
    quint16 driverPort() const        { return m_driverPort; }
    int     queueSize()  const        { return m_sendQueue.size(); }

    // ---- 6 契约虚函数 ----
    bool       doConnect(const QString& bindIp, quint16 port) override;
    int        recvPacket(QByteArray& inout, QByteArray& outPayload) override;
    bool       verifyPacket(const QByteArray& bytes) const override;
    QByteArray buildPacket(const QByteArray& payload) const override;

signals:
    void driverConnected(const QString& ip, quint16 port);
    void packetReceived(const QByteArray& payload);

protected:
    bool sendRaw(const QByteArray& bytes) override;

private slots:
    void onReadyRead();
    void onDrainSend();
    void onDrainRecv();

private:
    QUdpSocket*  m_socket = nullptr;
    QHostAddress m_driverIp;
    quint16      m_driverPort = 0;

    QQueue<QByteArray> m_sendQueue;
    QTimer*      m_sendTimer = nullptr;

    QQueue<QByteArray> m_recvQueue;
    QTimer*      m_recvTimer = nullptr;
};
