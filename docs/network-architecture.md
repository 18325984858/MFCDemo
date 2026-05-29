# Network ARK 网络架构与协议文档

> 来源:`NetDrv/`(WSK 内核驱动) + `QtApp/`(Qt6 控制端) + `Shared/Protocol.h`、`Shared/ProtocolRoute.h`
> 日期:2026-05-30

---

## 1. 总体架构

双机模型,**驱动端是 TCP 客户端 / UDP 客户端,App 端是 TCP 服务器 / UDP 服务器**。

| 角色 | 默认 IP | 模块 | 入口 |
|------|---------|------|------|
| 目标机(被控,内核驱动) | `192.168.1.50` | `NetDrv.sys` | [NetDrv/Driver.c](NetDrv/Driver.c) `DriverEntry` |
| 控制机(操作员,Qt UI) | `192.168.1.2`  | `ArkQt.exe`  | [QtApp/MainWindow.cpp](QtApp/MainWindow.cpp) |

IP/端口常量集中在 [Shared/Protocol.h](Shared/Protocol.h):

| 用途 | 端口 | 协议 |
|------|------|------|
| 旧版控制通道(兼容) | 9999 | UDP |
| TCP 控制通道(主) | 10000 | TCP |
| TCP 屏幕通道 | 10001 | TCP |
| TCP 文件通道 | 10002 | TCP |
| 目标机本地 agent | 9998 | UDP |

---

## 2. 初始化时序

### 2.1 驱动端(`NetDrv.sys`)

入口 [DriverEntry](NetDrv/Driver.c#L41):

```
DriverEntry
 ├─ DriverObject->DriverUnload = NetDrvUnload
 ├─ WSKStartup(1.0)                       // 注册 WSK Provider NPI
 ├─ NetDrvStartControlListener()          // 启动 UDP 控制线程
 └─ TcpLinkStart()                        // 启动 3 个 TCP 通道 + 心跳线程
```

#### UDP 控制线程 — [NetDrvControlThread](NetDrv/NetControl.c#L253)

1. `WSK_socket_ex(AF_INET, SOCK_DGRAM, IPPROTO_UDP, ...)` 创建数据报 socket,挂上 `WSK_CLIENT_DATAGRAM_DISPATCH.WskReceiveFromEvent = NetDrvReceiveFromEvent`(事件回调式接收,不轮询)。
2. `WSKBind` 到 `192.168.1.50:任意端口`(驱动作为客户端)。
3. `WSKControlSocket(SO_WSK_EVENT_CALLBACK, WSK_EVENT_RECEIVE_FROM)` 开启接收事件。
4. 主动 `WSKSendTo` 一个 `NDARK1|R|hello\n` 到 `192.168.1.2:9999` 完成注册。
5. 进入 `KeWaitForSingleObject(&g_CommandEvent, 5s)` 循环:超时发 `R|ping\n` 心跳;有事件就 `NetDrvTakeCommand` 从环形队列出队并 `NetDrvHandleCommand`。

#### TCP 链路 — [TcpLinkStart](NetDrv/TcpLink.c#L92)

为三类业务各起一个独立 `TCP_CHANNEL`(`control / screen / file`):

```
TcpChannelStart(ch)
 ├─ ConnectThread  (TcpChannelThread)  -- 不断重连 + 接收
 └─ SendThread     (TcpSendWorker)     -- 双优先级发送队列
```

`TcpChannelThread` 主循环([TcpChannel.c](NetDrv/TcpChannel.c#L226)):

```
loop:
  WSK_socket(SOCK_STREAM, IPPROTO_TCP)
  WSKConnect → 192.168.1.2 : channel.Port    // 驱动主动连
  TcpDoAuth(sock)                            // 8 字节头 + AUTH_KEY,读 ACK
  Channel->Connected = 1
  if SendHello: 发送 R|hello\n               // 仅 control 通道
  TcpRecvLoop(sock)                          // 阻塞接收成帧
  TcpChannelCloseIfCurrent()
  KeWait(3s) 重连
```

另起一条 `TcpPingThread`:每 5 秒在 `control` 通道发 `R|ping\n` 作为心跳。

### 2.2 App 端(`ArkQt.exe`)

[MainWindow](QtApp/MainWindow.cpp#L265) 启动时:

```
m_udp->start("0.0.0.0", 9999);              // UDP 监听
m_tcp->startServer("0.0.0.0", 10000);       // 内部会同时监听 10000/10001/10002
```

- `UdpLink::start`:`QUdpSocket::bind` + `readyRead` 信号驱动收包,发送通过 `QTimer` 节流的双队列。
- `TcpLink::startServer`:为 control/screen/file 各起一个 `TcpChannel`(`QTcpServer`)监听对应端口,`newConnection → readyRead` 流式拆帧。

### 2.3 启动顺序(双机配合)

```
 NetDrv DriverEntry            ArkQt startup
        │                            │
        │                            ├── UDP bind :9999
        │                            └── TCP listen 10000/10001/10002
        │── UDP sendto R|hello ─────►│   (UdpLink::onReadyRead)
        │                            │   driverConnected 信号
        │── TCP connect :10000 ─────►│
        │── AUTH frame (NDARK-...) ─►│
        │◄── ACK frame "1" ──────────│
        │── R|hello ────────────────►│
        │── TCP connect :10001 ─────►│  (同上鉴权)
        │── TCP connect :10002 ─────►│  (同上鉴权)
        │── R|ping (每 5s) ─────────►│
```

App 不主动连驱动 —— **总是驱动发起连接**(穿透目标机防火墙更容易,被控机一般不允许外部入站)。

---

## 3. 协议规格

### 3.1 UDP 帧(遗留通道,端口 9999)

文本协议,每个数据报独立成帧,固定 8 字节魔数前缀:

```
+---------+-----------------------------------------+
| NDARK1| | <payload, ASCII, 以 \n 结尾>            |
+---------+-----------------------------------------+
 7 bytes    最多 ~2 KB (NETDRV_CMD_SLOT_BYTES)
```

校验在 [NetDrvHasMagic](NetDrv/NetControl.c#L46):魔数不符的丢弃。

### 3.2 TCP 帧(主通道,端口 10000/10001/10002)

二进制定长头 + 文本/二进制负载:

```
偏移  大小  字段
0     4     magic   = 0x4E445232  ("NDR2" LE)
4     4     length  = payload 字节数 (LE, ≤ 16 MB)
8     N     payload
```

定义见 [Shared/Protocol.h](Shared/Protocol.h#L62):`NETDRV_TCP_FRAME_MAGIC` / `NETDRV_TCP_FRAME_HDR_SIZE` / `NETDRV_TCP_MAX_FRAME_SIZE`。

接收解帧:
- 驱动端 [TcpRecvLoop](NetDrv/TcpChannel.c#L185) 用 `TcpRecvExact` 同步拼齐 8 字节头,再读 `length` 字节负载,交给 `Channel->Dispatch → NetDrvDispatchCommand`。
- App 端 `TcpChannel::processBuffer` 在 `m_readBuf` 上做同样的状态机。

发送串行化:
- 驱动端每个通道两条链表(`SendListHigh / SendListNorm`),`TcpSendWorker` 消费,保证一次只有一条帧在发,避免交错。
- App 端通过 `QTcpSocket::write` 串行写;`bytesWritten` 信号反馈用于文件水位反压(`NETDRV_TCP_FILE_WRITE_WATERMARK = 1 MB`)。

### 3.3 鉴权握手 — [TcpDoAuth](NetDrv/TcpChannel.c#L150)

TCP 连接建立后,**驱动立即发送一帧**:

```
驱动 → App :  [hdr magic=NDR2 len=14] "NDARK-TCP-2026"
App  → 驱动:  [hdr magic=NDR2 len=1 ] "1"        // ACK,否则关闭
```

key 在 `NETDRV_TCP_AUTH_KEY`。App 端实现在 [TcpChannel.cpp#L125](QtApp/TcpChannel.cpp) 附近,匹配通过后才发 `authenticated` 信号、开始转发帧。

### 3.4 负载层文本协议

无论 UDP 还是 TCP,负载都是同一套 ASCII 文本协议(用 `|` 分隔字段,`\n` 收尾)。

| 方向 | 前缀 | 含义 |
|------|------|------|
| App → 驱动 | `C\|process\n` | 枚举进程 |
| App → 驱动 | `C\|driver\n` | 枚举驱动 |
| App → 驱动 | `C\|file\|<path>\n` | 枚举目录 |
| App → 驱动 | `C\|get\|<path>\n` | 下载文件 |
| App → 驱动 | `C\|put\|<path>\|<sizeHex>\|<chunkSz>\|<chunkCnt>\n` | 开始上传 |
| App → 驱动 | `P\|<data>\n` | 上传数据块 |
| App → 驱动 | `C\|putend\|<path>\|<sizeHex>\n` | 上传结束 |
| App → 驱动 | `C\|screenshot\n` / `C\|shotkey\n` | 截屏 / 强制关键帧 |
| App → 驱动 | `C\|stop\n` | 停止监听 |
| 驱动 → App | `R\|hello\n` / `R\|ping\n` | 注册 / 心跳 |
| 驱动 → App | `B\|<type>\|...` / `M\|<fields>` / `E\|<type>\|...` | 批结果(开始/数据/结束) |
| 驱动 → App | `F\|...` | 文件数据条目 |
| 驱动 → App | `Y\|...` / `Z\|...` | 屏幕关键帧 / 增量 |

完整常量见 [Shared/Protocol.h](Shared/Protocol.h#L78)。

### 3.5 三条 TCP 通道的负载分流

发送端按负载前缀路由到对应通道,实现在 [Shared/ProtocolRoute.h](Shared/ProtocolRoute.h):

- `NetDrvClassifyAppCommand`(App→驱动):
  - `C|screenshot` / `C|shotkey` → **screen** 通道
  - `C|file|` / `C|get|` / `C|put|` / `C|putend|` / `P|` → **file** 通道
  - 其余 → **control** 通道
- `NetDrvClassifyDriverPayload`(驱动→App):
  - `B|shot` / `E|shot` / `Y|` / `Z|` → **screen**
  - `B|file|` / `E|file|` / `F|` / `B|get|` / `E|get|` … → **file**
  - 其余 → **control**

好处:大流量(截屏 / 文件)不阻塞控制命令与心跳。

---

## 4. 收发核心数据流

### 4.1 驱动接收(UDP)

```
NIC → WSK Provider
     → NetDrvReceiveFromEvent(WSK_DATAGRAM_INDICATION 链表)
        ├─ MmGetSystemAddressForMdlSafe (映射 MDL)
        └─ NetDrvQueueCommand
              ├─ NetDrvHasMagic 校验 "NDARK1|"
              ├─ 拷贝到环形队列 g_CmdQueue[128][2048]
              └─ KeSetEvent(&g_CommandEvent)
NetDrvControlThread 唤醒
     └─ NetDrvTakeCommand → NetDrvHandleCommand
            ├─ 重命令(枚举/截屏/get) → 异步系统线程 AsyncCmdThread
            └─ 轻命令(put 块/stop/shotkey) → 直接处理
```

### 4.2 驱动接收(TCP)

```
TcpChannelThread::WSKConnect 成功
   └─ TcpDoAuth
   └─ TcpRecvLoop
         循环: TcpRecvExact(8) → 校验 magic/len → TcpRecvExact(len) → Channel->Dispatch
              └─ NetDrvDispatchCommand → NetDrvHandleCommand
```

### 4.3 驱动发送

- 业务代码统一调 `TcpLinkSend / TcpLinkSendHigh / TcpLinkSendString`,内部用 `NetDrvClassifyDriverPayload` 选通道,再 `TcpChannelSend` 入队 → 唤醒 `TcpSendWorker` → 加 8 字节头 → `WSKSend`。
- 兜底:若 `screen / file` 通道未连上,会回退到 `control` 通道发送([TcpLinkSendTo](NetDrv/TcpLink.c#L141))。
- 仍保留 `WSKSendTo` 走 UDP `NDARK1|` 发心跳与初次 `hello`。

### 4.4 App 接收/发送

- `UdpLink`:`readyRead → m_recvQueue → QTimer onDrainRecv → packetReceived` 信号上抛 `MainWindow::handleLine`。
- `TcpChannel`:`readyRead → m_readBuf` 状态机拼帧 → `packetReceived(channelId, payload)` → `TcpLink::onChannelPacket` 转发。
- 发送统一通过 `TcpLink::sendFrame / sendCommand`,内部按相同路由表选通道,封 8 字节头后 `QTcpSocket::write`。

---

## 5. 可靠性与控制点

| 机制 | 位置 | 作用 |
|------|------|------|
| 命令环形队列(128 槽 × 2 KB) | `NetControl.c` g_CmdQueue | 抗 `P|` 上传突发 |
| 队列满丢最旧 | `NetDrvQueueCommand` | 保留最新命令 |
| `g_AsyncCount + g_AsyncDone` | NetControl.c | Unload 前等所有异步命令线程结束 |
| `Closing/Connected/ActiveSends + SendIdleEvent` | TcpChannel.c | TCP socket 关闭安全栅栏 |
| 双优先级发送队列(High/Norm) | TcpChannel.c | 心跳/控制帧不被大数据淹没 |
| 5s `R\|ping`(UDP+TCP 各一份) | NetControl.c / TcpLink.c | 双向存活检测 |
| 16 MB 帧上限 | `NETDRV_TCP_MAX_FRAME_SIZE` | 防恶意长度内存炸 |
| 文件通道水位 1 MB | `NETDRV_TCP_FILE_WRITE_WATERMARK` | App 侧写盘反压 |
| Magic + AUTH_KEY 双校验 | TcpDoAuth / NetDrvHasMagic | 阻断误连/非协议流量 |

---

## 6. 协议一句话总结

> **TCP 主、UDP 辅;三条 TCP 通道(控制/屏幕/文件)分流,8 字节定长帧头(`NDR2`+len)封装同一套以 `|` 分隔的 ASCII 文本子协议;连接由驱动主动发起,握手用固定 AUTH_KEY,UDP 通道额外加 `NDARK1|` 魔数前缀做兼容。**
