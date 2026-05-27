#include "stdafx.h"
#include "ArkUdp.h"
#include "ArkDlg.h"
#include "../NetDrv/Ioctl.h"

bool CArkUdp::Start(LPCTSTR bindIp, UINT port)
{
    if (!Create(port, SOCK_DGRAM, FD_READ, bindIp)) {
        if (m_dlg) {
            m_dlg->Log(_T("UDP Create failed bind=%s:%u err=%u"),
                       bindIp, port, WSAGetLastError());
        }
        return false;
    }
    // Bump SO_RCVBUF so bursty file-download traffic (~8 MB/s, 10k+ small
    // datagrams/sec) doesn't drop chunks before OnReceive can drain them.
    int rcvBuf = 8 * 1024 * 1024;
    if (SetSockOpt(SO_RCVBUF, &rcvBuf, sizeof(rcvBuf)) == FALSE && m_dlg) {
        m_dlg->Log(_T("UDP SO_RCVBUF set FAILED err=%u"), WSAGetLastError());
    }
    if (m_dlg) {
        m_dlg->Log(_T("UDP Create OK bind=%s:%u rcvBuf=%d"), bindIp, port, rcvBuf);
    }
    return true;
}

bool CArkUdp::SendCommand(LPCSTR command)
{
    if (!command || !*command) {
        if (m_dlg) {
            m_dlg->Log(_T("UDP SendCommand rejected: empty command"));
        }
        return false;
    }

    char packet[1280] = { 0 };
    size_t commandLen = strlen(command);
    size_t packetLen = NETDRV_UDP_PACKET_MAGIC_LEN + commandLen;
    if (packetLen > sizeof(packet)) {
        if (m_dlg) {
            m_dlg->Log(_T("UDP SendCommand rejected: packetLen=%Iu cap=%Iu"),
                       packetLen, sizeof(packet));
        }
        return false;
    }

    memcpy(packet, NETDRV_UDP_PACKET_MAGIC, NETDRV_UDP_PACKET_MAGIC_LEN);
    memcpy(packet + NETDRV_UDP_PACKET_MAGIC_LEN, command, commandLen);
    int sent = SendTo(packet, (int)packetLen, NETDRV_UDP_PORT, NETDRV_DRIVER_IP_W);
    if (m_dlg) {
        if (sent == SOCKET_ERROR) {
            m_dlg->Log(_T("UDP SendTo FAILED target=%s:%u command=%S packetLen=%Iu err=%u"),
                       NETDRV_DRIVER_IP_W, NETDRV_UDP_PORT, command, packetLen, WSAGetLastError());
        } else {
            m_dlg->Log(_T("UDP SendTo OK target=%s:%u command=%S sent=%d packetLen=%Iu"),
                       NETDRV_DRIVER_IP_W, NETDRV_UDP_PORT, command, sent, packetLen);
        }
    }
    return sent != SOCKET_ERROR;
}

bool CArkUdp::SendAgentCommand(LPCSTR command)
{
    if (!command || !*command) {
        return false;
    }

    char packet[128] = { 0 };
    size_t commandLen = strlen(command);
    size_t packetLen = NETDRV_UDP_PACKET_MAGIC_LEN + commandLen;
    if (packetLen > sizeof(packet)) {
        return false;
    }

    memcpy(packet, NETDRV_UDP_PACKET_MAGIC, NETDRV_UDP_PACKET_MAGIC_LEN);
    memcpy(packet + NETDRV_UDP_PACKET_MAGIC_LEN, command, commandLen);
    int sent = SendTo(packet, (int)packetLen, NETDRV_SCREEN_AGENT_PORT, NETDRV_DRIVER_IP_W);
    if (m_dlg) {
        if (sent == SOCKET_ERROR) {
            m_dlg->Log(_T("UDP agent SendTo FAILED target=%s:%u command=%S packetLen=%Iu err=%u"),
                       NETDRV_DRIVER_IP_W, NETDRV_SCREEN_AGENT_PORT, command, packetLen, WSAGetLastError());
        } else {
            m_dlg->Log(_T("UDP agent SendTo OK target=%s:%u command=%S sent=%d packetLen=%Iu"),
                       NETDRV_DRIVER_IP_W, NETDRV_SCREEN_AGENT_PORT, command, sent, packetLen);
        }
    }
    return sent != SOCKET_ERROR;
}

void CArkUdp::OnReceive(int nErrorCode)
{
    if (nErrorCode != 0) {
        if (m_dlg) {
            m_dlg->Log(_T("UDP OnReceive error callback=%d"), nErrorCode);
        }
        return;
    }

    for (;;) {
        std::vector<char> buf(65536);
        CString peer; UINT peerPort = 0;
        int n = ReceiveFrom(buf.data(), (int)buf.size(), peer, peerPort);
        if (n <= 0) {
            int err = WSAGetLastError();
            if (err != WSAEWOULDBLOCK && m_dlg) {
                m_dlg->Log(_T("UDP ReceiveFrom stopped n=%d err=%d"), n, err);
            }
            break;
        }
        if (n < NETDRV_UDP_PACKET_MAGIC_LEN ||
            memcmp(buf.data(), NETDRV_UDP_PACKET_MAGIC, NETDRV_UDP_PACKET_MAGIC_LEN) != 0)
        {
            if (m_dlg) {
                m_dlg->Log(_T("UDP datagram dropped: invalid magic bytes=%d peer=%s:%u"),
                           n, peer, peerPort);
            }
            continue;
        }
        const char* payload = buf.data() + NETDRV_UDP_PACKET_MAGIC_LEN;
        int payloadLen = n - NETDRV_UDP_PACKET_MAGIC_LEN;
        if (m_dlg && payloadLen > 0 && payload[0] != 'Y' && payload[0] != 'G') {
            m_dlg->Log(_T("UDP datagram received bytes=%d peer=%s:%u tag=%c"),
                       n, peer, peerPort, payload[0]);
        }
        if (m_dlg) {
            m_dlg->OnArkPacket(payload, payloadLen);
        }
    }
}
