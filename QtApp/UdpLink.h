#pragma once
#include <QObject>
#include <QUdpSocket>
#include <QHostAddress>
#include <QQueue>
#include <QTimer>

class UdpLink : public QObject
{
    Q_OBJECT
public:
    explicit UdpLink(QObject* parent = nullptr);

    bool start(const QString& bindIp, quint16 port);
    void enqueue(const QByteArray& command);  // queued send
    bool sendCommand(const QByteArray& command);  // immediate send
    bool isDriverConnected() const { return m_connected; }
    QString driverAddr() const { return m_driverIp.toString(); }
    quint16 driverPort() const { return m_driverPort; }
    int queueSize() const { return m_sendQueue.size(); }

signals:
    void driverConnected(const QString& ip, quint16 port);
    void packetReceived(const QByteArray& payload);

private slots:
    void onReadyRead();
    void onDrainSend();
    void onDrainRecv();

private:
    QUdpSocket* m_socket = nullptr;
    bool        m_connected = false;
    QHostAddress m_driverIp;
    quint16      m_driverPort = 0;

    // send queue
    QQueue<QByteArray> m_sendQueue;
    QTimer*     m_sendTimer = nullptr;

    // receive queue
    QQueue<QByteArray> m_recvQueue;
    QTimer*     m_recvTimer = nullptr;
};
