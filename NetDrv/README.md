# NetDrv — WSK Network ARK Driver

Minimal Winsock Kernel (WSK) driver for remote ARK-style system enumeration,
file transfer, and screen capture over separated TCP channels with UDP kept as
a legacy fallback.

## Files

| File | Description |
| --- | --- |
| `Driver.c`       | `DriverEntry` / `Unload`, starts UDP control listener |
| `Wsk.h/.c`       | WSK wrappers: `WSKStartup` / `WSK_socket` / `WSKBind` / `WSKSendTo` / `WSK_closesocket` |
| `NetControl.c/.h`| UDP command dispatcher (receive event callback + worker thread) |
| `EnumArk.c/.h`   | Process / driver / file enumeration, file upload/download |
| `ScreenShot.c/.h` | Pure-kernel screen capture via GDI shellcode injection into dwm.exe |
| `TcpChannel.c/.h` | Reusable WSK TCP channel object: connect, auth, recv, send queue |
| `TcpLink.c/.h`    | Control/screen/file TCP channel manager |
| `ShellcodeGdi.c`  | PIC shellcode source (compiled separately, bytes embedded in driver) |
| `Ioctl.h`        | Shared protocol constants (IPs, ports, commands) |
| `NetDrv.inf`     | Install INF |
| `NetDrv.vcxproj` | WDK10 project (WDM, x64) |

## Design

- Single `WSK_REGISTRATION` + `WSK_PROVIDER_NPI`; registered in `DriverEntry`, released in `Unload`.
- Each WSK call: `IoAllocateIrp` + `IoSetCompletionRoutine` (signals `KEVENT`, returns `STATUS_MORE_PROCESSING_REQUIRED`) + caller `KeWaitForSingleObject` + read `Irp->IoStatus` + `IoFreeIrp`.
- Data buffers use `IoAllocateMdl` + `MmProbeAndLockPages` to build `WSK_BUF`.
- All network operations run in a system thread (`PsCreateSystemThread`) at PASSIVE_LEVEL.

## Protocol

The preferred path is TCP, with three physical channels to avoid head-of-line
blocking between realtime screen frames and bulk file transfer:

| Channel | Port | Purpose |
| --- | --- | --- |
| control | `10000` | commands, heartbeat, process/driver results, small status |
| screen | `10001` | screenshot requests and `B|shot2` / `Z|` / `E|shot2` frames |
| file | `10002` | directory enumeration, upload, download chunks |

All TCP messages use the shared `NDR2` length-prefixed frame format from
`Shared/Protocol.h`. `Shared/ProtocolRoute.h` classifies app commands and driver
payloads so both sides choose the same channel. UDP `9999` and `NDARK1|` framing
remain as a fallback.

## Build

Open `NetDrv.vcxproj` with Visual Studio + WDK10, select `x64 Release`, Build. Produces `NetDrv.sys` / `NetDrv.inf`.

## Install / Uninstall (test machine with testsigning enabled)

```
sc create NetDrv type= kernel binPath= C:\path\to\NetDrv.sys
sc start  NetDrv
sc stop   NetDrv
sc delete NetDrv
```
