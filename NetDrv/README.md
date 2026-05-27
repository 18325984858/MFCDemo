# NetDrv — WSK 网络收发样例驱动

参考 [libwsk](https://github.com/microsoft/libwsk-style) 风格写的最小 Winsock Kernel 驱动样例。

## 文件

| 文件 | 说明 |
| --- | --- |
| `Driver.c`     | `DriverEntry` / `Unload`，启动一个系统线程做 UDP/TCP 收发测试 |
| `Wsk.h/.c`     | WSK 封装：`WSKStartup` / `WSK_socket` / `WSKBind` / `WSKConnect` / `WSKSend` / `WSKReceive` / `WSKSendTo` / `WSKReceiveFrom` / `WSK_closesocket` |
| `NetDrv.inf`   | 安装 INF |
| `NetDrv.vcxproj` | WDK10 工程（WDM，x64） |

## 设计要点（与 libwsk 一致）

- 全局一份 `WSK_REGISTRATION` + `WSK_PROVIDER_NPI`，`DriverEntry` 注册，`Unload` 释放。
- 每次 WSK 调用：`IoAllocateIrp` → `IoSetCompletionRoutine`（完成时 `KeSetEvent` 并返回 `STATUS_MORE_PROCESSING_REQUIRED`）→ 调用者 `KeWaitForSingleObject` 等待 → 读 `Irp->IoStatus` → `IoFreeIrp`。
- 数据缓冲一律用 `IoAllocateMdl` + `MmProbeAndLockPages` 构造 `WSK_BUF`。
- 所有网络动作都在 `PsCreateSystemThread` 起的系统线程里跑，保证 PASSIVE_LEVEL。

## 自检行为（加载即触发）

1. UDP：向 `127.0.0.1:9999` 发一个 `"hello from NetDrv (UDP)"`。
2. TCP：连 `127.0.0.1:80`，发 `GET /` 并打印最多 256 字节回包。

用 DbgView / WinDbg 看 `[NetDrv]` 前缀的输出。

## 构建

用 Visual Studio + WDK10 打开 `NetDrv.vcxproj`，选 `x64`，Build。生成 `NetDrv.sys` / `NetDrv.inf`。

## 安装 / 卸载（测试机需开 testsigning）

```
sc create NetDrv type= kernel binPath= C:\path\to\NetDrv.sys
sc start  NetDrv
sc stop   NetDrv
sc delete NetDrv
```
