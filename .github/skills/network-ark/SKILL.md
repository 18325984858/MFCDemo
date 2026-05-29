---
name: network-ark
description: "Network ARK remote system inspector: dual-machine architecture with WSK kernel driver (NetDrv) on target and Qt UI (QtApp/ArkQt) on controller. Use when: building, deploying, adding commands/tabs, modifying UDP protocol, kernel driver development, screenshot capture, file enumeration, process listing, driver listing, or troubleshooting WSK/UDP communication."
---

# Network ARK — Project Skill

## Architecture

Two machines connected via UDP on port 9999:

| Role | IP (default) | Component | Description |
|------|-------------|-----------|-------------|
| Target (driver) | 192.168.1.179 | `NetDrv/` → `NetDrv.sys` | WDM kernel driver with WSK sockets, listens for commands |
| Controller (app) | 192.168.1.180 | `QtApp/` → `ArkQt.exe` | Qt6 GUI, sends commands, displays results |

All datagrams use `NDARK1|` magic prefix. Protocol constants in `NetDrv/Ioctl.h`.

## Project Layout

```
NetDrv/          WDK10 kernel driver (WDM, x64 Release)
  Driver.c       DriverEntry/Unload, starts UDP listener
  Wsk.c/h        WSK wrappers (socket/bind/send)
  NetControl.c/h UDP command dispatcher (event callback + worker thread ring queue)
  EnumArk.c/h    Process/driver/file enumeration, file upload/download
  ScreenShot.c/h Kernel screenshot via GDI shellcode into dwm.exe
  ShellcodeGdi.c PIC shellcode (compiled separately → ShellcodeGdiBytes.h)
  Ioctl.h        Shared protocol constants (IPs, ports, command strings)
  NetDrv.inf     Driver install INF

QtApp/           Qt6 Widgets + Network app (CMake + Ninja)
  main.cpp       Entry point
  MainWindow.cpp/h  Tabbed UI: process, driver, file browser, screenshot
  UdpLink.cpp/h     UDP send/receive, driver registration
  CMakeLists.txt    Qt6 (fallback Qt5), C++17, AUTOMOC

deploy/          Runtime dependencies for ArkQt (Qt DLLs, plugins)
build_all.cmd    Master build script (MSVC + WDK + CMake)
```

## Build

Run `build_all.cmd` from VS Developer Command Prompt (x64):

```
build_all.cmd
```

Steps:
1. **NetDrv.sys** — `msbuild NetDrv.vcxproj /p:Configuration=Release /p:Platform=x64`
2. **ArkQt.exe** — `cmake -G Ninja` + `cmake --build` (requires Qt6 at `C:/Qt/6.8.2/msvc2022_64`)

Outputs: `NetDrv.sys` (root), `deploy/ArkQt.exe`.

## Protocol — Adding a New Command

1. Define command string in `NetDrv/Ioctl.h`:
   ```c
   #define NETDRV_CMD_MY_THING  "C|mything\n"
   ```

2. Add handler in `NetDrv/NetControl.c` `NetDrvHandleCommand()`:
   ```c
   else if (strncmp(cmd, "C|mything", 9) == 0) { NetDrvMyThing(...); }
   ```
   - Prefix matches are order-sensitive: longer prefixes first (e.g. `C|putend|` before `C|put|`).

3. Send results back via WSK with `NDARK1|` protocol framing:
   - Begin: `B|mything|...\n`
   - Data: `M|<fields>\n`
   - End: `E|mything|...\n`

4. In `QtApp/MainWindow.cpp` `handleLine()`, parse the new response type.

5. In `QtApp/MainWindow.h`, add UI widgets and state for the new tab/feature.

## Protocol — Response Framing

| Pattern | Purpose |
|---------|---------|
| `B\|<type>\|...` | Begin batch |
| `E\|<type>\|...` | End batch |
| `P\|<pid>\|<name>\|...` | Process entry |
| `D\|<name>\|<path>\|...` | Driver entry |
| `F\|<isDir>\|<sizeHex>\|<nameHex>` | File entry |
| `G\|<idx>\|<offHex>\|<lenHex>\|<dataHex>` | File download chunk |
| `Y\|<fid>\|<idx>\|<offHex>\|<lenHex>\|<dataHex>` | Screenshot chunk (V1 hex, legacy) |
| `Z\|<binary header+data>` | Screenshot chunk (V2 binary: 4B fid + 4B idx + 4B off + 4B len + raw RLE data) |
| `S\|<status>` | Status/ack |
| `R\|hello` / `R\|ping` | Driver registration/heartbeat |
| `U\|<pid>\|<userHex>\|<cmdHex>` | Process enrichment from agent |

## Key Constraints

- **WSK event callback**: Control receive uses `WskReceiveFromEvent + SO_WSK_EVENT_CALLBACK`. Do NOT add synchronous `WskReceiveFrom` polling — causes `0x139` on Win10 19041.
- **Ring queue**: `NetControl.c` uses 128-slot ring buffer for incoming commands. Single `g_Command` slot was replaced to avoid overwrites during bulk transfers.
- **WSK IRP lifecycle**: Every WSK downcall must check `STATUS_PENDING` before waiting on KEVENT; fast `WskSendTo` can cause double-complete crash (`0x44`) otherwise.
- **Hex encoding**: Binary data (file content, names with non-ASCII) is hex-encoded in UDP payloads to avoid `\n` delimiter conflicts. Screenshot V2 uses binary `Z|` packets instead.
- **Screenshot V2 protocol**: Uses frame diff (XOR with prev) + RLE compression + binary transport. Header `B|shot2|fid|w|h|rawHex|compHex|chunkSz|chunkCnt|isKey` (text), chunks `Z|<binary>` (not `\n`-delimited), trailer `E|shot2|fid|compHex` (text). App detects `Z|` prefix in `onPacket()` to bypass `\n` splitting.
- **GBK source files**: Some `.cpp` files may be GBK-encoded (cp936). Check encoding before editing; do not blindly write UTF-8 into GBK files.
- **Kernel API availability**: Win10 19041 ntoskrnl does not export `PsSuspendThread`, `ZwTerminateThread`, etc. Use user-mode alternatives or `MmGetSystemRoutineAddress` with NULL checks.

## Deploy to Target Machine

```
sc create NetDrv type= kernel binPath= C:\path\to\NetDrv.sys
sc start  NetDrv
```
Requires test-signing enabled (`bcdedit /set testsigning on`).

## Deploy Controller

Copy `deploy/` folder (with `ArkQt.exe` + Qt runtime DLLs) to the controller machine and run `ArkQt.exe`.
