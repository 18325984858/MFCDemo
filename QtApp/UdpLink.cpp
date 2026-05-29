// UdpLink.cpp --- UDP 实现(继承 NetLinkBase)。
#include "UdpLink.h"
#include "Ioctl.h"#include "../Shared/NdarkLog.h"
#include <QDebug>
#include <cstring>

UdpLink::UdpLink(QObject* parent)
    : NetLinkBase("udp", parent)
{
    m_sendTimer = new QTimer(this);
    m_sendTimer->setInterval(1);
    connect(m_sendTimer, &QTimer::timeout, this, &UdpLink::onDrainSend);

    m_recvTimer = new QTimer(this);
    m_recvTimer->setInterval(1);
    connect(m_recvTimer, &QTimer::timeout, this, &UdpLink::onDrainRecv);
}

// ============================================================
// 6 契约方法实现
// ============================================================

bool UdpLink::doConnect(const QString& bindIp, quint16 port)
{
    if (m_socket) return true;
    m_socket = new QUdpSocket(this);
    QHostAddress addr = bindIp.isEmpty() ? QHostAddress::AnyIPv4
                                         : QHostAddress(bindIp);
    if (!m_socket->bind(addr, port)) {
        NDARK_LOG_ERR("udp bind %s:%u failed: %s",
                      qPrintable(bindIp), port,
                      qPrintable(m_socket->errorString()));
        delete m_socket;
        m_socket = nullptr;
        return false;
    }
    m_socket->setSocketOption(QAbstractSocket::ReceiveBufferSizeSocketOption,
                              8 * 1024 * 1024);
    connect(m_socket, &QUdpSocket::readyRead, this, &UdpLink::onReadyRead);
    NDARK_LOG_INFO("udp listening on %s:%u", qPrintable(bindIp), port);
    // UDP 无主动心跳,仅依靠 touchRx() 跟踪 lastRxMs 供 msSinceLastRx() 查询。
    return true;
}

bool UdpLink::verifyPacket(const QByteArray& bytes) const
{
    if (bytes.size() < NETDRV_UDP_PACKET_MAGIC_LEN) return false;
    return memcmp(bytes.constData(), NETDRV_UDP_PACKET_MAGIC,
                  NETDRV_UDP_PACKET_MAGIC_LEN) == 0;
}

QByteArray UdpLink::buildPacket(const QByteArray& payload) const
{
    QByteArray pkt(NETDRV_UDP_PACKET_MAGIC, NETDRV_UDP_PACKET_MAGIC_LEN);
    pkt.append(payload);
    return pkt;
}

int UdpLink::recvPacket(QByteArray& inout, QByteArray& outPayload)
{
    // UDP 是面向报文的:inout 要么是完整的一帧,要么是空。
    if (inout.isEmpty()) return 0;
    if (!verifyPacket(inout)) return -1;
    outPayload = inout.mid(NETDRV_UDP_PACKET_MAGIC_LEN);
    const int consumed = inout.size();
    inout.clear();
    return consumed;
}

bool UdpLink::sendRaw(const QByteArray& bytes)
{
    if (!m_socket || !isConnected()) return false;
    qint64 sent = m_socket->writeDatagram(bytes, m_driverIp, m_driverPort);
    return sent == bytes.size();
}

// ============================================================
// 旧公共 API(MainWindow 调用)
// ============================================================

bool UdpLink::start(const QString& bindIp, quint16 port)
{
    return doConnect(bindIp, port);
}

bool UdpLink::sendCommand(const QByteArray& command)
{
    return sendPacket(command);
}

void UdpLink::enqueue(const QByteArray& command)
{
    m_sendQueue.enqueue(command);
    if (!m_sendTimer->isActive())
        m_sendTimer->start();
}

void UdpLink::onDrainSend()
{
    if (m_sendQueue.isEmpty() || !isConnected()) {
        m_sendTimer->stop();
        return;
    }
    for (int i = 0; i < 4 && !m_sendQueue.isEmpty(); ++i)
        sendCommand(m_sendQueue.dequeue());
    if (m_sendQueue.isEmpty())
        m_sendTimer->stop();
}

void UdpLink::onReadyRead()
{
    while (m_socket->hasPendingDatagrams()) {
        QByteArray buf(int(m_socket->pendingDatagramSize()), 0);
        QHostAddress peer;
        quint16      peerPort = 0;
        m_socket->readDatagram(buf.data(), buf.size(), &peer, &peerPort);

        QByteArray payload;
        int n = recvPacket(buf, payload);
        if (n <= 0 || payload.isEmpty()) continue;

        touchRx();

        // R|hello / R|ping:立即处理,避免被节流影响连接判定。
        if (payload.size() >= 2 && payload[0] == 'R' && payload[1] == '|') {
            const bool wasConnected = isConnected();
            m_driverIp   = peer;
            m_driverPort = peerPort;
            setConnected(true);
            if (!wasConnected) {
                NDARK_LOG_INFO("udp driver hello from %s:%u",
                               qPrintable(peer.toString()), peerPort);
                emit driverConnected(peer.toString(), peerPort);
            }
            continue;
        }

        m_recvQueue.enqueue(payload);
    }

    if (!m_recvQueue.isEmpty() && !m_recvTimer->isActive())
        m_recvTimer->start();
}

void UdpLink::onDrainRecv()
{
    if (m_recvQueue.isEmpty()) {
        m_recvTimer->stop();
        return;
    }
    for (int i = 0; i < 32 && !m_recvQueue.isEmpty(); ++i)
        emit packetReceived(m_recvQueue.dequeue());
    if (m_recvQueue.isEmpty())
        m_recvTimer->stop();
}
