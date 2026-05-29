//
// ProtocolRoute.h --- shared TCP channel routing helpers.
// Used by both the kernel driver and the Qt controller app.
//

#pragma once

#include "Protocol.h"

#define NETDRV_TCP_CHANNEL_CONTROL 0
#define NETDRV_TCP_CHANNEL_SCREEN  1
#define NETDRV_TCP_CHANNEL_FILE    2
#define NETDRV_TCP_CHANNEL_COUNT   3

static __inline int NetDrvPayloadStartsWith(const char* data,
                                            unsigned long len,
                                            const char* prefix)
{
    unsigned long i = 0;
    if (!data || !prefix)
        return 0;
    while (prefix[i] != 0) {
        if (i >= len || data[i] != prefix[i])
            return 0;
        ++i;
    }
    return 1;
}

static __inline unsigned short NetDrvTcpPortForChannel(int channel)
{
    switch (channel) {
    case NETDRV_TCP_CHANNEL_SCREEN:
        return NETDRV_TCP_SCREEN_PORT;
    case NETDRV_TCP_CHANNEL_FILE:
        return NETDRV_TCP_FILE_PORT;
    case NETDRV_TCP_CHANNEL_CONTROL:
    default:
        return NETDRV_TCP_CONTROL_PORT;
    }
}

static __inline int NetDrvClassifyAppCommand(const char* data, unsigned long len)
{
    if (!data || len == 0)
        return NETDRV_TCP_CHANNEL_CONTROL;

    if (NetDrvPayloadStartsWith(data, len, "C|screenshot") ||
        NetDrvPayloadStartsWith(data, len, "C|shotkey")) {
        return NETDRV_TCP_CHANNEL_SCREEN;
    }

    if (NetDrvPayloadStartsWith(data, len, "C|file|") ||
        NetDrvPayloadStartsWith(data, len, "C|get|") ||
        NetDrvPayloadStartsWith(data, len, "C|put|") ||
        NetDrvPayloadStartsWith(data, len, "C|putend|") ||
        NetDrvPayloadStartsWith(data, len, "P|")) {
        return NETDRV_TCP_CHANNEL_FILE;
    }

    return NETDRV_TCP_CHANNEL_CONTROL;
}

static __inline int NetDrvClassifyDriverPayload(const char* data, unsigned long len)
{
    if (!data || len == 0)
        return NETDRV_TCP_CHANNEL_CONTROL;

    if (NetDrvPayloadStartsWith(data, len, "B|shot") ||
        NetDrvPayloadStartsWith(data, len, "E|shot") ||
        NetDrvPayloadStartsWith(data, len, "Y|") ||
        NetDrvPayloadStartsWith(data, len, "Z|")) {
        return NETDRV_TCP_CHANNEL_SCREEN;
    }

    if (NetDrvPayloadStartsWith(data, len, "B|file|") ||
        NetDrvPayloadStartsWith(data, len, "E|file|") ||
        NetDrvPayloadStartsWith(data, len, "F|") ||
        NetDrvPayloadStartsWith(data, len, "B|get|") ||
        NetDrvPayloadStartsWith(data, len, "E|get|") ||
        NetDrvPayloadStartsWith(data, len, "G|")) {
        return NETDRV_TCP_CHANNEL_FILE;
    }

    return NETDRV_TCP_CHANNEL_CONTROL;
}
