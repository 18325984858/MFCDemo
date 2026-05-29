// NetLinkBase.cpp --- shared scaffolding for UDP / TCP links.
#include "NetLinkBase.h"
#include "../Shared/NdarkLog.h"

#include <QTimer>
#include <QDateTime>

NetLinkBase::NetLinkBase(const QString& name, QObject* parent)
    : QObject(parent), m_name(name)
{
}

NetLinkBase::~NetLinkBase() = default;

void NetLinkBase::heartbeat()
{
    // 基类默认实现:派发给子类的 tick 钩子。子类若需要更复杂逻辑可覆盖整个 heartbeat()。
    heartbeatTick();
}

bool NetLinkBase::sendPacket(const QByteArray& payload)
{
    if (!m_connected) return false;
    QByteArray bytes = buildPacket(payload);
    if (bytes.isEmpty() && !payload.isEmpty()) return false;
    return sendRaw(bytes);
}

void NetLinkBase::setConnected(bool ok)
{
    if (m_connected == ok) return;
    m_connected = ok;
    NDARK_LOG_INFO("link[%s] connected=%d", qPrintable(m_name), ok ? 1 : 0);
    emit connectedChanged(ok);
}

void NetLinkBase::enableHeartbeat(int intervalMs)
{
    if (intervalMs <= 0) {
        if (m_heartbeatTimer) m_heartbeatTimer->stop();
        return;
    }
    // 延迟到 doConnect() 调用时创建,以保证 QTimer 与当前线程亲和。
    if (!m_heartbeatTimer) {
        m_heartbeatTimer = new QTimer(this);
        connect(m_heartbeatTimer, &QTimer::timeout,
                this, &NetLinkBase::onHeartbeatTimeout);
    }
    m_heartbeatTimer->start(intervalMs);
}

void NetLinkBase::touchRx()
{
    m_lastRxMs = QDateTime::currentMSecsSinceEpoch();
}

qint64 NetLinkBase::msSinceLastRx() const
{
    if (m_lastRxMs < 0) return -1;
    return QDateTime::currentMSecsSinceEpoch() - m_lastRxMs;
}

void NetLinkBase::onHeartbeatTimeout()
{
    heartbeat();
}
