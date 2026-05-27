#include "UdpLink.h"
#include "Ioctl.h"
#include <QVariant>
#include <QDebug>

UdpLink::UdpLink(QObject* parent) : QObject(parent)
{
    m_drainTimer = new QTimer(this);
    m_drainTimer->setInterval(1);  // 1ms between queued sends
    connect(m_drainTimer, &QTimer::timeout, this, &UdpLink::onDrainQueue);
}

bool UdpLink::start(const QString& bindIp, quint16 port)
{
    m_socket = new QUdpSocket(this);
    QHostAddress addr = bindIp.isEmpty() ? QHostAddress::AnyIPv4
                                         : QHostAddress(bindIp);
    if (!m_socket->bind(addr, port)) {
        qWarning() << "UDP bind failed:" << m_socket->errorString();
        return false;
    }
    m_socket->setSocketOption(QAbstractSocket::ReceiveBufferSizeSocketOption,
                              8 * 1024 * 1024);
    connect(m_socket, &QUdpSocket::readyRead, this, &UdpLink::onReadyRead);
    qDebug() << "UDP listening on" << bindIp << port;
    return true;
}

bool UdpLink::sendCommand(const QByteArray& command)
{
    if (!m_connected || !m_socket) {
        qDebug() << "sendCommand: driver not connected";
        return false;
    }
    QByteArray pkt(NETDRV_UDP_PACKET_MAGIC, NETDRV_UDP_PACKET_MAGIC_LEN);
    pkt.append(command);
    qint64 sent = m_socket->writeDatagram(pkt, m_driverIp, m_driverPort);
    return sent == pkt.size();
}

void UdpLink::enqueue(const QByteArray& command)
{
    m_sendQueue.enqueue(command);
    if (!m_drainTimer->isActive())
        m_drainTimer->start();
}

void UdpLink::onDrainQueue()
{
    if (m_sendQueue.isEmpty() || !m_connected) {
        m_drainTimer->stop();
        return;
    }
    // Send up to 4 packets per tick to balance throughput and UI responsiveness
    for (int i = 0; i < 4 && !m_sendQueue.isEmpty(); ++i) {
        sendCommand(m_sendQueue.dequeue());
    }
    if (m_sendQueue.isEmpty())
        m_drainTimer->stop();
}

void UdpLink::onReadyRead()
{
    while (m_socket->hasPendingDatagrams()) {
        QByteArray buf(m_socket->pendingDatagramSize(), 0);
        QHostAddress peer;
        quint16 peerPort = 0;
        m_socket->readDatagram(buf.data(), buf.size(), &peer, &peerPort);

        if (buf.size() < NETDRV_UDP_PACKET_MAGIC_LEN)
            continue;
        if (memcmp(buf.constData(), NETDRV_UDP_PACKET_MAGIC,
                   NETDRV_UDP_PACKET_MAGIC_LEN) != 0)
            continue;

        QByteArray payload = buf.mid(NETDRV_UDP_PACKET_MAGIC_LEN);
        if (payload.isEmpty()) continue;

        // R|hello / R|ping — driver registration
        if (payload.size() >= 2 && payload[0] == 'R' && payload[1] == '|') {
            bool wasConnected = m_connected;
            m_driverIp   = peer;
            m_driverPort = peerPort;
            m_connected  = true;
            if (!wasConnected)
                emit driverConnected(peer.toString(), peerPort);
            continue;
        }

        emit packetReceived(payload);
    }
}
