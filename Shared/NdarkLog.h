/*++
    NdarkLog.h --- Unified logging facility for Network ARK.

    Single header included by **both** the kernel driver (NetDrv) and the
    user-mode Qt controller (ArkQt). It exposes one family of macros:

        NDARK_LOG_TRACE(fmt, ...)
        NDARK_LOG_INFO (fmt, ...)
        NDARK_LOG_WARN (fmt, ...)
        NDARK_LOG_ERR  (fmt, ...)
        NDARK_LOG(fmt, ...)            // alias for NDARK_LOG_INFO

    Where the output lands:

      - Kernel side (NetDrv.sys): DbgPrintEx with DPFLTR_IHVDRIVER_ID.
        Visible in the kernel WinDbg session attached to the target machine,
        and in DebugView (with "Capture Kernel" enabled). Each line is
        prefixed with "[NDARK][K]".
      - User-mode side (ArkQt.exe): OutputDebugStringA. Visible in DebugView
        or in a WinDbg user-mode session attached to ArkQt.exe (no kernel
        debugger required). Each line is prefixed with "[NDARK][U]".

    A single kernel WinDbg session cannot natively display both kernel and
    user-mode prints; the practical setup is:

        Target VM kernel -> WinDbg (Kernel)         <- driver lines
        Host  ArkQt.exe  -> DebugView / WinDbg (UM) <- app lines

    The shared "[NDARK]" prefix and level tag make the two streams easy to
    grep and correlate side by side.

    Compile-time level filter: define NDARK_LOG_LEVEL before including this
    header to drop messages at or below the threshold. Defaults: TRACE when
    DBG is defined (kernel Debug) or _DEBUG (user-mode Debug), INFO otherwise.
--*/
#pragma once

#define NDARK_LOG_LEVEL_TRACE   0
#define NDARK_LOG_LEVEL_INFO    1
#define NDARK_LOG_LEVEL_WARN    2
#define NDARK_LOG_LEVEL_ERR     3
#define NDARK_LOG_LEVEL_NONE    4

#ifndef NDARK_LOG_LEVEL
#  if defined(DBG) || defined(_DEBUG)
#    define NDARK_LOG_LEVEL  NDARK_LOG_LEVEL_TRACE
#  else
#    define NDARK_LOG_LEVEL  NDARK_LOG_LEVEL_INFO
#  endif
#endif

/* ============================================================
 * Kernel-mode implementation (NetDrv.sys)
 * ============================================================ */
#if defined(_KERNEL_MODE) || defined(NDARK_KERNEL)

#include <ntddk.h>

#define NDARK_LOG_SINK_(lvlTag, fmt, ...) \
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, \
               "[NDARK][K][" lvlTag "] " fmt "\n", ##__VA_ARGS__)

/* ============================================================
 * User-mode implementation (ArkQt.exe)
 * ============================================================ */
#else

#include <windows.h>
#include <stdio.h>
#include <stdarg.h>

static __inline void NdarkLogEmit_(const char* lvlTag, const char* fmt, ...)
{
    char    msg[1024];
    char    line[1100];
    va_list ap;
    int     n;
    va_start(ap, fmt);
    n = _vsnprintf_s(msg, sizeof(msg), _TRUNCATE, fmt, ap);
    va_end(ap);
    if (n < 0) n = 0;
    _snprintf_s(line, sizeof(line), _TRUNCATE,
                "[NDARK][U][%s] %s\n", lvlTag, msg);
    OutputDebugStringA(line);
}

#define NDARK_LOG_SINK_(lvlTag, fmt, ...) \
    NdarkLogEmit_(lvlTag, fmt, ##__VA_ARGS__)

#endif

/* ============================================================
 * Public macros with compile-time level filter
 * ============================================================ */
#if NDARK_LOG_LEVEL <= NDARK_LOG_LEVEL_TRACE
#  define NDARK_LOG_TRACE(fmt, ...) NDARK_LOG_SINK_("TRC", fmt, ##__VA_ARGS__)
#else
#  define NDARK_LOG_TRACE(fmt, ...) ((void)0)
#endif

#if NDARK_LOG_LEVEL <= NDARK_LOG_LEVEL_INFO
#  define NDARK_LOG_INFO(fmt, ...)  NDARK_LOG_SINK_("INF", fmt, ##__VA_ARGS__)
#else
#  define NDARK_LOG_INFO(fmt, ...)  ((void)0)
#endif

#if NDARK_LOG_LEVEL <= NDARK_LOG_LEVEL_WARN
#  define NDARK_LOG_WARN(fmt, ...)  NDARK_LOG_SINK_("WRN", fmt, ##__VA_ARGS__)
#else
#  define NDARK_LOG_WARN(fmt, ...)  ((void)0)
#endif

#if NDARK_LOG_LEVEL <= NDARK_LOG_LEVEL_ERR
#  define NDARK_LOG_ERR(fmt, ...)   NDARK_LOG_SINK_("ERR", fmt, ##__VA_ARGS__)
#else
#  define NDARK_LOG_ERR(fmt, ...)   ((void)0)
#endif

#define NDARK_LOG(fmt, ...) NDARK_LOG_INFO(fmt, ##__VA_ARGS__)
