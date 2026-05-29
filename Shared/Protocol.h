//
// Protocol.h --- Shared protocol definitions for Network ARK.
// Used by both the kernel driver (NetDrv) and the Qt controller app (ArkQt).
//

#pragma once

// ============================================================
//  Network Endpoints
// ============================================================
#define NETDRV_DRIVER_IP_A      "192.168.1.50"
#define NETDRV_DRIVER_IP_W      L"192.168.1.50"
#define NETDRV_DRIVER_IP_B1     192
#define NETDRV_DRIVER_IP_B2     168
#define NETDRV_DRIVER_IP_B3     1
#define NETDRV_DRIVER_IP_B4     50

#define NETDRV_APP_IP_A         "192.168.1.2"
#define NETDRV_APP_IP_W         L"192.168.1.2"
#define NETDRV_APP_IP_B1        192
#define NETDRV_APP_IP_B2        168
#define NETDRV_APP_IP_B3        1
#define NETDRV_APP_IP_B4        2

// ============================================================
//  Ports
// ============================================================
#define NETDRV_UDP_PORT          9999   // legacy UDP
#define NETDRV_TCP_PORT          10000  // primary TCP link
#define NETDRV_TCP_CONTROL_PORT  NETDRV_TCP_PORT
#define NETDRV_TCP_SCREEN_PORT   10001
#define NETDRV_TCP_FILE_PORT     10002
#define NETDRV_SCREEN_AGENT_PORT 9998

// ============================================================
//  TCP channel sizing / backpressure
// ============================================================
#define NETDRV_TCP_SCREEN_CHUNK_BYTES   (64u * 1024u)
#define NETDRV_TCP_FILE_WRITE_WATERMARK (1024u * 1024u)

// ============================================================
//  UDP legacy framing (kept for backward compatibility)
// ============================================================
#define NETDRV_UDP_PACKET_MAGIC      "NDARK1|"
#define NETDRV_UDP_PACKET_MAGIC_LEN  7

// ============================================================
//  TCP frame format
//
//  Each message on the TCP stream is framed as:
//    [4 bytes] magic  = NETDRV_TCP_FRAME_MAGIC  (little-endian)
//    [4 bytes] length = payload byte count       (little-endian)
//    [length bytes] payload
//
//  The payload content uses the same text protocol as UDP
//  (command strings, B|/E| batches, Z| binary chunks, etc.)
//  but WITHOUT the "NDARK1|" prefix --- TCP framing replaces it.
// ============================================================
#define NETDRV_TCP_FRAME_MAGIC      0x4E445232u  // "NDR2" LE
#define NETDRV_TCP_FRAME_HDR_SIZE   8
#define NETDRV_TCP_MAX_FRAME_SIZE   (16u * 1024u * 1024u)  // 16 MB

// ============================================================
//  TCP authentication handshake
//
//  After TCP connect the driver sends an AUTH frame whose payload
//  is exactly NETDRV_TCP_AUTH_KEY.  The app validates it and
//  responds with a single-byte ACK frame (payload "1") or
//  closes the connection.
// ============================================================
#define NETDRV_TCP_AUTH_KEY         "NDARK-TCP-2026"
#define NETDRV_TCP_AUTH_KEY_LEN     14

// ============================================================
//  App -> Driver control commands
// ============================================================
#define NETDRV_CMD_ENUM_PROCESS  "C|process\n"
#define NETDRV_CMD_ENUM_DRIVER   "C|driver\n"
#define NETDRV_CMD_ENUM_FILE     "C|file|"      // + UTF-8 path + '\n'
#define NETDRV_CMD_GET_FILE      "C|get|"       // + UTF-8 path + '\n'
#define NETDRV_CMD_PUT_BEGIN     "C|put|"       // + path|sizeHex|chunkSz|chunkCnt\n
#define NETDRV_CMD_PUT_END       "C|putend|"    // + path|sizeHex\n
#define NETDRV_CMD_STOP          "C|stop\n"
#define NETDRV_CMD_SCREENSHOT    "C|screenshot\n"
#define NETDRV_CMD_SHOT_KEYFRAME "C|shotkey\n"

// ============================================================
//  Driver -> App registration / heartbeat
// ============================================================
#define NETDRV_REG_HELLO         "R|hello\n"
#define NETDRV_REG_PING          "R|ping\n"

// ============================================================
//  Driver -> local target-side agent
// ============================================================
#define NETDRV_AGENT_CMD_PROCESS "A|process\n"
#define NETDRV_AGENT_CMD_PING    "A|ping\n"
