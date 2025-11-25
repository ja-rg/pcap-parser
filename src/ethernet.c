#include "ethernet.h"

// helper: lee 16 bits en big endian sin asumir alineación
static uint16_t be16_read(const uint8_t *p)
{
    return (uint16_t)((p[0] << 8) | p[1]);
}

// Implementación pública: rellena eth_header y devuelve true si el parse fue exitoso.
bool parse_ethernet_header(const uint8_t *packet_data,
                           size_t packet_length,
                           ethernet_header_t *eth_header)
{
    if (!packet_data || !eth_header)
    {
        return false;
    }

    if (packet_length < ETHERNET_MIN_HEADER_SIZE)
    {
        return false;
    }

    ethernet_header_t info;
    memset(&info, 0, sizeof(info));

    memcpy(info.dest_mac, packet_data, 6);
    memcpy(info.src_mac, packet_data + 6, 6);

    uint16_t type_or_len = be16_read(packet_data + 12);

    if (type_or_len == 0x8100 || type_or_len == 0x88A8 || type_or_len == 0x9100)
    {
        if (packet_length < 18)
        {
            return false;
        }
        info.frame_type = ETH_FRAME_VLAN;
        info.vlan_tci = be16_read(packet_data + 14);
        info.vlan_id = info.vlan_tci & 0x0FFF;
        info.ethertype = be16_read(packet_data + 16);
        info.header_length = 18;
    }
    else if (type_or_len >= 0x0600)
    {
        info.frame_type = ETH_FRAME_ETHERNET_II;
        info.ethertype = type_or_len;
        info.header_length = 14;
    }
    else
    {
        info.frame_type = ETH_FRAME_8023_LLC;
        info.ethertype = 0;
        info.header_length = 14;
    }

    *eth_header = info;
    eth_header->siguiente_capa = (void *)(packet_data + info.header_length);
    return true;
}
