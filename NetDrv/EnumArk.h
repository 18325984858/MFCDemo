//
// EnumArk.h - kernel-side enumerators.
// Style mirrors MyDriver64\Interface.c: EnumProcessInfo / EnumDriverInfo.
//

#pragma once

#include <ntddk.h>

//
// Walk all processes via ZwQuerySystemInformation(SystemProcessInformation)
// and emit one UDP datagram per process to NETDRV_APP_IP:NETDRV_UDP_PORT.
//   Line format (ASCII, '\n' terminated):
//     P|<pid>|<parentPid>|<imageName>\n
// Begin/end markers ("B\n" / "E\n") are emitted around the batch.
//
NTSTATUS NetDrvEnumProcess(VOID);

//
// Walk loaded kernel modules via ZwQuerySystemInformation(SystemModuleInformation)
// and emit one UDP datagram per driver:
//     D|<baseHex>|<size>|<fullPath>\n
//
NTSTATUS NetDrvEnumDriver(VOID);

//
// Enumerate the directory at <utf8Path> (Win32 path, e.g. "C:\"). Emits one
// UDP datagram per entry to NETDRV_APP_IP:NETDRV_UDP_PORT:
//     F|<isDir 0/1>|<sizeHex>|<nameHexUtf8>\n
// Bracketed by B|file|<pathHex>\n / E|file|<pathHex>\n.
//
NTSTATUS NetDrvEnumFile(_In_z_ PCSTR Utf8Path);
//
// File download. Reads the file at <utf8Path> and emits B|get| header,
// many G|<idx>|<offHex>|<lenHex>|<dataHex>\n chunks, then E|get|.
//
NTSTATUS NetDrvGetFile(_In_z_ PCSTR Utf8Path);

//
// File upload from app. NetDrvPutBegin opens the destination file from a
// C|put|<utf8Path>|<sizeHex>|<chunkSize>|<chunkCount> line; NetDrvPutChunk
// writes one P|<idx>|<offHex>|<lenHex>|<dataHex> chunk; NetDrvPutEnd commits
// from C|putend|<utf8Path>|<sizeHex>. Only one upload may be active at a time.
//
NTSTATUS NetDrvPutBegin(_In_z_ PCSTR HeaderRest);
NTSTATUS NetDrvPutChunk(_In_z_ PCSTR ChunkRest);
NTSTATUS NetDrvPutEnd  (_In_z_ PCSTR EndRest);