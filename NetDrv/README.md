# NetDrv — WSK Network ARK Driver

Minimal Winsock Kernel (WSK) driver for remote ARK-style system enumeration and screen capture over UDP.

## Files

| File | Description |
| --- | --- |
| `Driver.c`       | `DriverEntry` / `Unload`, starts UDP control listener |
| `Wsk.h/.c`       | WSK wrappers: `WSKStartup` / `WSK_socket` / `WSKBind` / `WSKSendTo` / `WSK_closesocket` |
| `NetControl.c/.h`| UDP command dispatcher (receive event callback + worker thread) |
| `EnumArk.c/.h`   | Process / driver / file enumeration, file upload/download |
| `ScreenShot.c/.h` | Pure-kernel screen capture via GDI shellcode injection into dwm.exe |
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

Driver listens on `NETDRV_DRIVER_IP:9999`, streams results to `NETDRV_APP_IP:9999`.
All datagrams start with `NDARK1|` magic. Commands: `C|process`, `C|driver`, `C|file|<path>`, `C|get|<path>`, `C|put|...`, `C|screenshot`, `C|stop`.

## Build

Open `NetDrv.vcxproj` with Visual Studio + WDK10, select `x64 Release`, Build. Produces `NetDrv.sys` / `NetDrv.inf`.

## Install / Uninstall (test machine with testsigning enabled)

```
sc create NetDrv type= kernel binPath= C:\path\to\NetDrv.sys
sc start  NetDrv
sc stop   NetDrv
sc delete NetDrv
```
