#pragma once
#include <QObject>
#include <QUdpSocket>
#include <QHostAddress>

class UdpLink : public QObject
{
    Q_OBJECT
public:
    explicit UdpLink(QObject* parent = nullptr);

    bool start(const QString& bindIp, quint16 port);
    bool sendCommand(const QByteArray& command);
    bool isDriverConnected() const { return m_connected; }
    QString driverAddr() const { return m_driverIp.toString(); }
    quint16 driverPort() const { return m_driverPort; }

signals:
    void driverConnected(const QString& ip, quint16 port);
    void packetReceived(const QByteArray& payload);

private slots:
    void onReadyRead();

private:
    QUdpSocket* m_socket = nullptr;
    bool        m_connected = false;
    QHostAddress m_driverIp;
    quint16      m_driverPort = 0;
};
