#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifndef ETHERNET_H
#define ETHERNET_H

#include <stdio.h>  // for snprintf

// Tamaño mínimo de un header Ethernet base (sin VLAN)
#define ETHERNET_MIN_HEADER_SIZE 14

typedef enum
{
    HTTP = 0
} Protocols_t;

typedef enum
{
    ETH_FRAME_UNKNOWN = 0,
    ETH_FRAME_ETHERNET_II,   // Dest, Src, Ethertype
    ETH_FRAME_VLAN,          // Dest, Src, TPID(8100/88A8/9100), TCI, Ethertype interno
    ETH_FRAME_8023_LLC       // Dest, Src, Length + LLC/SNAP después
} ethernet_frame_type_t;

// Ethertypes más comunes
typedef enum
{
    ETHERTYPE_IPV4 = 0x0800,
    ETHERTYPE_ARP  = 0x0806,
    ETHERTYPE_IPV6 = 0x86DD
} ethertype_t;

typedef struct
{
    uint8_t dest_mac[6];
    uint8_t src_mac[6];

    // Tipo de frame según el campo type/length
    ethernet_frame_type_t frame_type;

    // Para Ethernet II o VLAN: Ethertype de la capa 3 (IPv4, ARP, IPv6, etc.)
    uint16_t ethertype;

    // Solo si frame_type == ETH_FRAME_VLAN
    uint16_t vlan_tci;
    uint16_t vlan_id;

    // Bytes totales de cabecera de enlace antes del payload de capa 3 (IP, LLC, etc.)
    size_t header_length;

    // Pointer to the next protocol header (e.g., IP header)
    void *siguiente_capa;
} ethernet_header_t;

// Función para parsear header Ethernet desde datos crudos
// Devuelve true en éxito y rellena `eth_header`. No realiza malloc;
// `eth_header->siguiente_capa` apuntará dentro de `packet_data`.
bool parse_ethernet_header(const uint8_t *packet_data,
                           size_t packet_length,
                           ethernet_header_t *eth_header);

/*
  MAC printing helpers

  Usage examples:
    printf(MAC_FMT_STR " -> " MAC_FMT_STR "\n", MAC_ARGS(src), MAC_ARGS(dest));
    char buf[18];
    mac_to_string(buf, mac);
    puts(buf);

  Format chosen: "aa:bb:cc:dd:ee:ff" (lowercase hex, zero-padded).
  Buffer size required: 17 chars + NUL = 18.
*/

#define MAC_FMT_STR "%02x:%02x:%02x:%02x:%02x:%02x"
#define MAC_ARGS(mac) \
    ((unsigned int)(mac)[0]), ((unsigned int)(mac)[1]), ((unsigned int)(mac)[2]), \
    ((unsigned int)(mac)[3]), ((unsigned int)(mac)[4]), ((unsigned int)(mac)[5])

// Convenience macro for printing a MAC directly with printf:
// printf(MAC_PRINT(m), args...); expands to printf("%02x:...%02x", MAC_ARGS(m))
#define MAC_PRINT(mac) MAC_FMT_STR, MAC_ARGS(mac)

// Convert MAC to a NUL-terminated string into a buffer of at least 18 bytes.
static inline void mac_to_string(char out[18], const uint8_t mac[6])
{
    // snprintf returns number of bytes that would have been written (excluding NUL).
    // We ignore the return value because buffer length is fixed and sufficient.
    (void)snprintf(out, 18, MAC_FMT_STR, MAC_ARGS(mac));
}

#endif // ETHERNET_H
