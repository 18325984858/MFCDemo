/*++
    TcpLink.h --- Kernel TCP link manager for Network ARK.
--*/

#pragma once

#include <ntddk.h>

NTSTATUS TcpLinkStart(VOID);
VOID TcpLinkStop(VOID);

NTSTATUS TcpLinkSend(_In_reads_bytes_(Len) const VOID* Data, _In_ ULONG Len);
NTSTATUS TcpLinkSendHigh(_In_reads_bytes_(Len) const VOID* Data, _In_ ULONG Len);
NTSTATUS TcpLinkSendString(_In_z_ const CHAR* Str);

NTSTATUS TcpLinkSendControl(_In_reads_bytes_(Len) const VOID* Data, _In_ ULONG Len);
NTSTATUS TcpLinkSendControlString(_In_z_ const CHAR* Str);
NTSTATUS TcpLinkSendScreen(_In_reads_bytes_(Len) const VOID* Data, _In_ ULONG Len);
NTSTATUS TcpLinkSendScreenString(_In_z_ const CHAR* Str);
NTSTATUS TcpLinkSendFile(_In_reads_bytes_(Len) const VOID* Data, _In_ ULONG Len);
NTSTATUS TcpLinkSendFileString(_In_z_ const CHAR* Str);

BOOLEAN TcpLinkIsConnected(VOID);
BOOLEAN TcpLinkIsScreenConnected(VOID);
BOOLEAN TcpLinkIsFileConnected(VOID);
