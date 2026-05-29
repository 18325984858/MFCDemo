// NetLinkBase.h --- Abstract base for all Network ARK link types.
//
// Defines the 6-method contract every concrete link (UDP / TCP) must honour:
//   1. doConnect      建链 / 监听 / 握手
//   2. heartbeat      心跳调度(基类提供 QTimer,子类填 heartbeatTick)
//   3. recvPacket     从一段原始字节里拆一帧业务载荷(状态机入口)
//   4. sendPacket     发送一帧业务载荷(buildPacket + sendRaw)
//   5. verifyPacket   校验入包合法性(magic / length / AUTH)
//   6. buildPacket    把业务载荷封装为线缆字节
//
// 子类只需重写 doConnect / recvPacket / verifyPacket / buildPacket / sendRaw
// 即可,sendPacket 与 heartbeat 在基类提供默认骨架。
//
#pragma once

#include <QObject>
#include <QByteArray>
#include <QString>

class QTimer;

class NetLinkBase : public QObject
{
    Q_OBJECT
public:
    explicit NetLinkBase(const QString& name, QObject* parent = nullptr);
    ~NetLinkBase() override;

    // ---- 6 契约方法 ----
    /// 1. 连接:启动监听 / 绑定 / 握手。bindIp 为空表示 0.0.0.0。
    virtual bool doConnect(const QString& bindIp, quint16 port) = 0;

    /// 2. 心跳:由基类 QTimer 周期触发,默认实现调用 heartbeatTick()。
    virtual void heartbeat();

    /// 3. 收包:在 inout 缓冲区上做状态机拆帧,成功时把载荷放入 outPayload
    ///         并返回消费的字节数(>0);0=不完整需等待;<0=帧错应断开。
    virtual int  recvPacket(QByteArray& inout, QByteArray& outPayload) = 0;

    /// 4. 发送包:基类默认 buildPacket → sendRaw,子类可覆盖。
    virtual bool sendPacket(const QByteArray& payload);

    /// 5. 验证包:校验头部 magic / length / AUTH 等。
    virtual bool verifyPacket(const QByteArray& bytes) const = 0;

    /// 6. 构建包:把业务载荷封装成线缆字节(UDP 加 NDARK1|,TCP 加 NDR2+len)。
    virtual QByteArray buildPacket(const QByteArray& payload) const = 0;

    // ---- 公共状态 ----
    bool    isConnected() const { return m_connected; }
    QString linkName()    const { return m_name; }

signals:
    void connectedChanged(bool connected);
    /// 已经经过 verifyPacket + buildPacket 反向拆解的纯业务载荷
    void packetReady(const QByteArray& payload);

protected:
    /// 子类:真正把字节写入 socket。
    virtual bool sendRaw(const QByteArray& bytes) = 0;
    /// 子类:每个心跳周期执行的动作(发 ping / 检查超时等)。
    virtual void heartbeatTick() {}

    void setConnected(bool ok);
    /// 子类:开启心跳调度。intervalMs <= 0 表示停用。
    void enableHeartbeat(int intervalMs);
    /// 子类:每次成功收到一帧后调用,用于刷新 lastRxMs。
    void touchRx();
    /// 自上次 RX 经过的毫秒数;无 RX 记录时返回 -1。
    qint64 msSinceLastRx() const;

private slots:
    void onHeartbeatTimeout();

private:
    QString m_name;
    QTimer* m_heartbeatTimer = nullptr;
    qint64  m_lastRxMs = -1;
    bool    m_connected = false;
};
