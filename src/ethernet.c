#include "ethernet.h"

// helper: lee 16 bits en big endian sin asumir alineación
static uint16_t be16_read(const uint8_t *p)
{
    return (uint16_t)((p[0] << 8) | p[1]);
}

bool parse_ethernet_header(const uint8_t *packet_data,
                           size_t packet_length,
                           ethernet_header_t *eth_header)
{
    if (!packet_data || !eth_header) {
        return false;
    }

    // Necesitamos al menos el header Ethernet mínimo
    if (packet_length < ETHERNET_MIN_HEADER_SIZE) {
        return false;
    }

    ethernet_header_t info = {0};

    // Copiar MACs
    memcpy(info.dest_mac, packet_data, 6);
    memcpy(info.src_mac,  packet_data + 6, 6);

    // Campo type/length / TPID en bytes 12–13
    uint16_t type_or_len = be16_read(packet_data + 12);

    // 1) Detectar VLAN (802.1Q, QinQ, etc.)
    if (type_or_len == 0x8100 || type_or_len == 0x88A8 || type_or_len == 0x9100) {
        // Necesitamos: 14 (MACs+TPID) + 2 (TCI) + 2 (Ethertype interno)
        if (packet_length < 18) {
            return false;
        }

        info.frame_type = ETH_FRAME_VLAN;
        info.vlan_tci   = be16_read(packet_data + 14);
        info.vlan_id    = info.vlan_tci & 0x0FFF;   // 12 bits bajos

        // Ethertype real de capa 3 (IPv4, IPv6, etc.)
        info.ethertype   = be16_read(packet_data + 16);
        info.header_length = 18; // Dest+Src+TPID+TCI+Ethertype

        *eth_header = info;
        return true;
    }

    // 2) Ethernet II vs 802.3 según el valor de type_or_len
    if (type_or_len >= 0x0600) {
        // Ethernet II "plano"
        info.frame_type    = ETH_FRAME_ETHERNET_II;
        info.ethertype     = type_or_len;
        info.header_length = 14;  // 6+6+2
    } else {
        // 802.3 con LLC/SNAP; type_or_len es longitud
        info.frame_type    = ETH_FRAME_8023_LLC;
        info.ethertype     = 0;   // no hay Ethertype directo
        info.header_length = 14;
    }

    *eth_header = info;
    return true;
}
