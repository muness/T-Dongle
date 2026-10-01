#include "lwip/dns.h"
#include "gateway.h"
#include "lwip/inet.h"
#include "lwip/sockets.h"
#include <strings.h>
static uint16_t read16(const uint8_t *p) { return (p[0] << 8) | p[1]; }
static void write16(uint8_t *p, uint16_t n) {
    p[0] = n >> 8;
    p[1] = n;
}
static void dns_task(void *arg) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in local = {
        .sin_family = AF_INET, .sin_port = htons(53), .sin_addr.s_addr = htonl(0xc0a84d01)};
    if (sock < 0 || bind(sock, (struct sockaddr *)&local, sizeof(local)) < 0) {
        if (sock >= 0)
            close(sock);
        vTaskDelete(NULL);
        return;
    }
    uint8_t packet[1500];
    for (;;) {
        struct sockaddr_in host;
        socklen_t sl = sizeof(host);
        int n = recvfrom(sock, packet, sizeof(packet), 0, (struct sockaddr *)&host, &sl);
        if (n < 12 || (ntohl(host.sin_addr.s_addr) & 0xffffff00) != 0xc0a84d00 ||
            read16(packet + 4) != 1 || packet[2] & 128)
            continue;
        char name[256];
        size_t pos = 12, len = 0;
        bool invalid = false;
        while (pos < (size_t)n && packet[pos]) {
            unsigned size = packet[pos++];
            if (size > 63 || pos + size > (size_t)n || len + size + 1 >= sizeof(name)) {
                invalid = true;
                break;
            }
            if (len)
                name[len++] = '.';
            memcpy(name + len, packet + pos, size);
            len += size;
            pos += size;
        }
        if (invalid || pos + 5 > (size_t)n)
            continue;
        name[len] = 0;
        pos++;
        unsigned type = read16(packet + pos), klass = read16(packet + pos + 2);
        pos += 4;
        bool tailnet = len >= 8 && !strcasecmp(name + len - 8, ".tailnet");
        uint32_t alias = 0;
        if (tailnet && type == 1 && klass == 1 &&
            xSemaphoreTake(members_lock, pdMS_TO_TICKS(50)) == pdTRUE) {
            unsigned matches = 0;
            for (membership_t *m = members; m; m = m->next)
                if (m->client && m->client->state == ML_STATE_CONNECTED) {
                    for (int i = 0; i < m->client->peer_count; i++) {
                        ml_peer_t *p = &m->client->peers[i];
                        char peer[64], qualified[128];
                        strlcpy(peer, p->hostname, sizeof(peer));
                        char *dot = strchr(peer, '.');
                        if (dot)
                            *dot = 0;
                        snprintf(qualified, sizeof(qualified), "%s.%s.tailnet", peer, m->label);
                        if (!strcasecmp(name, qualified) && p->vpn_ip) {
                            matches++;
                            alias = gateway_alias(m->id, p->vpn_ip);
                        }
                    }
                }
            if (matches != 1)
                alias = 0;
            xSemaphoreGive(members_lock);
        }
        if (tailnet) {
            packet[2] = 0x81;
            packet[3] = alias ? 0x80 : 0x83;
            write16(packet + 6, alias ? 1 : 0);
            write16(packet + 8, 0);
            write16(packet + 10, 0);
            if (alias && pos + 16 <= sizeof(packet)) {
                uint8_t answer[] = {0xc0, 0x0c, 0, 1, 0,           1,           0,          0,
                                    0,    30,   0, 4, alias >> 24, alias >> 16, alias >> 8, alias};
                memcpy(packet + pos, answer, 16);
                pos += 16;
            }
            sendto(sock, packet, pos, 0, (struct sockaddr *)&host, sl);
            continue;
        }
        /* Forward ordinary DNS only to the Wi-Fi-provided resolver. Match the
         * reply's transaction ID; connect() pins the resolver source. */
        const ip_addr_t *resolver = dns_getserver(0);
        if (ip_addr_isany(resolver) || !IP_IS_V4(resolver))
            continue;
        struct sockaddr_in upstream = {.sin_family = AF_INET,
                                       .sin_port = htons(53),
                                       .sin_addr.s_addr = ip4_addr_get_u32(ip_2_ip4(resolver))};
        int out = socket(AF_INET, SOCK_DGRAM, 0);
        if (out < 0)
            continue;
        struct timeval timeout = {.tv_sec = 2};
        setsockopt(out, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        uint16_t id = read16(packet);
        if (connect(out, (struct sockaddr *)&upstream, sizeof(upstream)) == 0 &&
            send(out, packet, n, 0) == n) {
            int count = recv(out, packet, sizeof(packet), 0);
            if (count >= 12 && read16(packet) == id && (packet[2] & 128))
                sendto(sock, packet, count, 0, (struct sockaddr *)&host, sl);
        }
        close(out);
    }
}
void gateway_dns_start(void) { xTaskCreate(dns_task, "gateway_dns", 4096, NULL, 3, NULL); }
