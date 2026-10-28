#include "protocols.h"
#include "queue.h"
#include "lib.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <arpa/inet.h>

#define WAITING_BUCKETS 256


struct tree_node {
    struct tree_node *kids[2];
    struct route_table_entry *route;
};

struct packet_in_asteptare {
    char *buf;
    size_t lenght;
    uint32_t next_hop_ip;
    int out_interface;
};

struct arp_packet {
    struct ether_hdr eth;
    struct arp_hdr arp;
};

struct waiting_bucket {
    uint32_t next_hop_ip;
    queue packets;
    struct waiting_bucket *next;
};

struct waiting_bucket *waiting[WAITING_BUCKETS];
struct arp_table_entry *arp_tablou;
struct route_table_entry *tabel_rutare;
int arp_tablou_l;
int arp_tablou_cap;
int tabel_routare_lungime;

struct tree_node *creeaza_nod_nou() {
    struct tree_node *new_node = malloc(sizeof(struct tree_node));
    new_node->kids[0] = NULL;
    new_node->kids[1] = NULL;
    new_node->route = NULL;
    return new_node;
}

void adauga_in_trie(struct tree_node *root, struct route_table_entry *entry) {
    struct tree_node *aux = root;
    uint32_t prefix = ntohl(entry->prefix);
    uint32_t mask = ntohl(entry->mask);

    int length_mask = 0;
    while (length_mask < 32 && (mask & (1U << (31 - length_mask)))) {
        length_mask++;
    }

    for (int i = 0; i < length_mask; i++) {
        int bit = (prefix >> (31 - i)) & 1;
        if (!aux->kids[bit]) {
            aux->kids[bit] = creeaza_nod_nou();
        }
        aux = aux->kids[bit];
    }

    aux->route = entry;
}

struct route_table_entry *cauta_in_trie(struct tree_node *root, uint32_t ip_dest) {
    struct tree_node *aux = root;
    struct route_table_entry *best_match = NULL;
    uint32_t ip = ntohl(ip_dest);

    for (int i = 0; i < 32; i++) {
        int bit = (ip >> (31 - i)) & 1;
        if (!aux->kids[bit]) {
            break;
        }
        aux = aux->kids[bit];

        if (aux->route != NULL) {
            best_match = aux->route;
        }
    }
    return best_match;
}

struct tree_node *construieste_trie_rutare() {
    struct tree_node *root = creeaza_nod_nou();
    for (int i = 0; i < tabel_routare_lungime; i++) {
        adauga_in_trie(root, &tabel_rutare[i]);
    }
    printf("[DEBUG] Trie construit.\n");
    return root;
}

struct arp_table_entry *cauta_arp(uint32_t ip) {
    int stanga = 0, dreapta = arp_tablou_l - 1;

    while (stanga <= dreapta) {
        int mijloc = stanga + (dreapta - stanga) / 2;
        if (arp_tablou[mijloc].ip == ip)
            return &arp_tablou[mijloc];
        if (arp_tablou[mijloc].ip < ip)
            stanga = mijloc + 1;
        else
            dreapta = mijloc - 1;
    }

    return NULL;
}

void adauga_in_arp_cache(uint32_t ip, uint8_t *mac) {
    int stanga = 0, dreapta = arp_tablou_l - 1;

    while (stanga <= dreapta) {
        int mijloc = stanga + (dreapta - stanga) / 2;
        if (arp_tablou[mijloc].ip == ip) {
            memcpy(arp_tablou[mijloc].mac, mac, 6);
            return;
        }
        if (arp_tablou[mijloc].ip < ip)
            stanga = mijloc + 1;
        else
            dreapta = mijloc - 1;
    }

    if (arp_tablou_l == arp_tablou_cap) {
        arp_tablou_cap *= 2;
        arp_tablou = realloc(arp_tablou, sizeof(struct arp_table_entry) * arp_tablou_cap);
        DIE(!arp_tablou, "error at realloc arp_tablou");
    }

    for (int i = arp_tablou_l; i > stanga; i--) {
        arp_tablou[i] = arp_tablou[i - 1];
    }

    arp_tablou[stanga].ip = ip;
    memcpy(arp_tablou[stanga].mac, mac, 6);
    arp_tablou_l++;
    printf("[DEBUG] Intrare noua in ARP Cache pentru IP: %s\n", inet_ntoa(*(struct in_addr*)&ip));
}

static unsigned waiting_hash(uint32_t ip) {
    return (unsigned)((ip ^ (ip >> 16)) & (WAITING_BUCKETS - 1));
}

static queue get_waiting_queue(uint32_t next_hop_ip, bool create) {
    unsigned idx = waiting_hash(next_hop_ip);
    struct waiting_bucket *bucket = waiting[idx];

    while (bucket) {
        if (bucket->next_hop_ip == next_hop_ip)
            return bucket->packets;
        bucket = bucket->next;
    }

    if (!create)
        return NULL;

    bucket = malloc(sizeof(*bucket));
    DIE(bucket == NULL, "error allocating waiting bucket");
    bucket->next_hop_ip = next_hop_ip;
    bucket->packets = create_queue();
    bucket->next = waiting[idx];
    waiting[idx] = bucket;
    return bucket->packets;
}

static void init_ethernet_header(struct ether_hdr *eth, uint8_t *destination_mac, int out_interface) {
    get_interface_mac(out_interface, eth->ethr_shost);
    if (destination_mac) {
        memcpy(eth->ethr_dhost, destination_mac, 6);
    } else {
        memset(eth->ethr_dhost, 0xFF, 6);
    }
    eth->ethr_type = htons(0x0806);
}

static void init_arp_header(struct arp_hdr *arp, uint32_t src_ip, uint32_t target_ip, uint8_t *target_hw, int out_interface, uint16_t opcode) {
    arp->hw_type    = htons(1);
    arp->proto_type = htons(0x0800);
    arp->hw_len     = 6;
    arp->proto_len  = 4;
    arp->opcode     = htons(opcode);
    get_interface_mac(out_interface, arp->shwa);
    arp->sprotoa = src_ip;
    if (target_hw) {
        memcpy(arp->thwa, target_hw, 6);
    } else {
        memset(arp->thwa, 0x00, 6);
    }
    arp->tprotoa = target_ip;
}

void trimite_arp_request(uint32_t target_ip, int out_interface) {
    printf("[DEBUG] Trimit ARP Request pentru IP: %s pe interfata %d\n",
            inet_ntoa(*(struct in_addr*)&target_ip), out_interface);

    size_t packet_len = sizeof(struct arp_packet);
    uint8_t *packet = calloc(1, packet_len);
    DIE(packet == NULL, "error allocating packet buffer");

    struct arp_packet packet_struct;

    init_ethernet_header(&packet_struct.eth, NULL, out_interface);

    struct in_addr src_addr;
    inet_aton(get_interface_ip(out_interface), &src_addr);
    init_arp_header(&packet_struct.arp, src_addr.s_addr, target_ip, NULL, out_interface, 1);

    memcpy(packet, &packet_struct, packet_len);

    send_to_link(packet_len, (char *)packet, out_interface);
    free(packet);
}

void proceseaza_arp_reply(struct arp_hdr *arp) {
    printf("[DEBUG] Primit ARP Reply de la IP: %s\n", inet_ntoa(*(struct in_addr*)&arp->sprotoa));

    adauga_in_arp_cache(arp->sprotoa, arp->shwa);

    queue packet_queue = get_waiting_queue(arp->sprotoa, false);
    if (!packet_queue) {
        printf("[DEBUG] Niciun pachet in asteptare pentru acest IP.\n");
        return;
    }

    int count = 0;
    while (!queue_empty(packet_queue)) {
        struct packet_in_asteptare *new_packet = queue_deq(packet_queue);
        struct ether_hdr *new_ethernet_header = (struct ether_hdr *)new_packet->buf;

        get_interface_mac(new_packet->out_interface, new_ethernet_header->ethr_shost);
        memcpy(new_ethernet_header->ethr_dhost, arp->shwa, 6);

        new_ethernet_header->ethr_type = htons(0x0800);

        send_to_link(new_packet->lenght, new_packet->buf, new_packet->out_interface);

        free(new_packet->buf);
        free(new_packet);
        count++;
    }
    printf("[DEBUG] Trimise %d pachete care asteptau acest reply.\n", count);
}

void proceseaza_arp_request(struct ether_hdr *eth_in, struct arp_hdr *arp_in, int in_interface) {
    struct in_addr addr;
    inet_aton(get_interface_ip(in_interface), &addr);

    if (addr.s_addr != arp_in->tprotoa) {
        return;
    }

    printf("[DEBUG] Primit ARP Request pentru IP-ul meu pe interfata %d. Trimit Reply.\n", in_interface);

    size_t packet_len = sizeof(struct arp_packet);
    uint8_t *packet = calloc(1, packet_len);
    DIE(packet == NULL, "error allocating packet buffer");

    struct arp_packet packet_struct;

    init_ethernet_header(&packet_struct.eth, eth_in->ethr_shost, in_interface);
    init_arp_header(&packet_struct.arp, addr.s_addr, arp_in->sprotoa, arp_in->shwa, in_interface, 2);

    memcpy(packet, &packet_struct, packet_len);

    send_to_link(packet_len, (char *)packet, in_interface);
    free(packet);
}

void handle_arp(char *buf, int interface) {
    struct ether_hdr *eth = (struct ether_hdr *)buf;
    struct arp_hdr   *arp = (struct arp_hdr *)(buf + sizeof(struct ether_hdr));

    uint16_t opcode = ntohs(arp->opcode);

    printf("[DEBUG] Pachet ARP detectat pe interfata %d (Opcode: %d).\n", interface, opcode);

    if (opcode == 1)
        proceseaza_arp_request(eth, arp, interface);
    else if (opcode == 2)
        proceseaza_arp_reply(arp);
}

static void init_ip_header(struct ip_hdr *ip, uint32_t saddr, uint32_t daddr, uint16_t len, uint8_t proto) {
    ip->ver = 4;
    ip->ihl = 5;
    ip->tos = 0;
    ip->tot_len = htons(len);
    ip->id = htons(1);
    ip->frag = 0;
    ip->ttl = 64;
    ip->proto = proto;
    ip->source_addr = saddr;
    ip->dest_addr = daddr;
    ip->checksum = 0;
    ip->checksum = htons(checksum((uint16_t *)ip, sizeof(struct ip_hdr)));
}

static void init_icmp_header(struct icmp_hdr *icmp, uint8_t type, uint8_t code) {
    icmp->mtype = type;
    icmp->mcode = code;
    icmp->check = 0;
}

void trimite_icmp(int in_interface, struct ether_hdr *eth_intrare, struct ip_hdr *ip_intrare, uint8_t type, uint8_t code) {
    size_t ip_hdr_len = ip_intrare->ihl * 4;
    size_t icmp_hdr_len = sizeof(struct icmp_hdr);
    size_t icmp_data_len = ip_hdr_len + 8;
    size_t total_len = sizeof(struct ether_hdr) + sizeof(struct ip_hdr) + icmp_hdr_len + icmp_data_len;

    char packet[1500] = {0};

    struct ether_hdr *eth_iesire = (struct ether_hdr *)packet;
    struct ip_hdr *ip_iesire = (struct ip_hdr *)(packet + sizeof(struct ether_hdr));
    struct icmp_hdr *icmp = (struct icmp_hdr *)(packet + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));
    uint8_t *icmp_payload = (uint8_t *)icmp + icmp_hdr_len;

    get_interface_mac(in_interface, eth_iesire->ethr_shost);
    memcpy(eth_iesire->ethr_dhost, eth_intrare->ethr_shost, 6);
    eth_iesire->ethr_type = htons(0x0800);

    struct in_addr my_addr;
    inet_aton(get_interface_ip(in_interface), &my_addr);

    init_ip_header(ip_iesire, my_addr.s_addr, ip_intrare->source_addr,
                   total_len - sizeof(struct ether_hdr), 1);

    init_icmp_header(icmp, type, code);

    memcpy(icmp_payload, ip_intrare, icmp_data_len);

    icmp->check = htons(checksum((uint16_t *)icmp, icmp_hdr_len + icmp_data_len));

    send_to_link(total_len, packet, in_interface);
}

void trimite_icmp_echo_reply(int in_interface, struct ether_hdr *eth_intrare, struct ip_hdr *ip_intrare, char *buf, size_t len) {
    size_t ip_hdr_len = ip_intrare->ihl * 4;
    struct icmp_hdr *icmp = (struct icmp_hdr *)(buf + sizeof(struct ether_hdr) + ip_hdr_len);
    size_t icmp_total = len - sizeof(struct ether_hdr) - ip_hdr_len;

    memcpy(eth_intrare->ethr_dhost, eth_intrare->ethr_shost, 6);
    get_interface_mac(in_interface, eth_intrare->ethr_shost);

    uint32_t aux = ip_intrare->source_addr;
    ip_intrare->source_addr = ip_intrare->dest_addr;
    ip_intrare->dest_addr = aux;

    ip_intrare->checksum = 0;
    ip_intrare->checksum = htons(checksum((uint16_t *)ip_intrare, ip_hdr_len));

    icmp->mtype = 0;

    icmp->check = 0;
    icmp->check = htons(checksum((uint16_t *)icmp, icmp_total));

    send_to_link(len, buf, in_interface);
}

void aloca_si_citeste_tabele(char *nume_fisier_rutare) {
    arp_tablou_cap = 100;
    arp_tablou = malloc(sizeof(struct arp_table_entry) * arp_tablou_cap);
    DIE(arp_tablou == NULL, "error allocating arp_tablou");
    arp_tablou_l = 0;

    tabel_rutare = malloc(sizeof(struct route_table_entry) * 80000);
    DIE(tabel_rutare == NULL, "error allocating tabel_routare");
    tabel_routare_lungime = read_rtable(nume_fisier_rutare, tabel_rutare);
    printf("[DEBUG] Tabela de rutare incarcata (%d intrari).\n", tabel_routare_lungime);
}

bool este_pachet_pentru_mine(struct ip_hdr *ip_header) {
    for (int i = 0; i < ROUTER_NUM_INTERFACES; i++) {
        struct in_addr addr;
        inet_aton(get_interface_ip(i), &addr);
        if (addr.s_addr == ip_header->dest_addr) {
            return true;
        }
    }
    return false;
}

bool pachet_valid_checksum_si_ttl(struct ip_hdr *ip_header,
                                   struct ether_hdr *e_header,
                                   int interface) {
    uint16_t old_checksum = ip_header->checksum;
    ip_header->checksum = 0;
    if (checksum((uint16_t *)ip_header, ip_header->ihl * 4) != ntohs(old_checksum)) {
        printf("[DEBUG] Pachet aruncat: Checksum invalid.\n");
        ip_header->checksum = old_checksum;
        return false;
    }
    ip_header->checksum = old_checksum;

    if (ip_header->ttl <= 1) {
        printf("[DEBUG] Pachet aruncat: TTL expirat.\n");
        trimite_icmp(interface, e_header, ip_header, 11, 0);
        return false;
    }

    return true;
}

void proceseaza_si_trimite(struct tree_node *root, char *buf, size_t len,
                           struct ether_hdr *e_header, struct ip_hdr *ip_header,
                           int interface) {
    struct route_table_entry *best_route = cauta_in_trie(root, ip_header->dest_addr);
    if (best_route == NULL) {
        printf("[DEBUG] Pachet aruncat: Ruta negasita pentru %s.\n", inet_ntoa(*(struct in_addr*)&ip_header->dest_addr));
        trimite_icmp(interface, e_header, ip_header, 3, 0);
        return;
    }

    ip_header->ttl--;
    ip_header->checksum = 0;
    ip_header->checksum = htons(checksum((uint16_t *)ip_header, ip_header->ihl * 4));

    struct arp_table_entry *arp_entry = cauta_arp(best_route->next_hop);
    if (arp_entry == NULL) {
        printf("[DEBUG] MAC negasit in cache pentru next_hop %s. Pun pachetul in coada.\n",
                inet_ntoa(*(struct in_addr*)&best_route->next_hop));

        queue packet_queue = get_waiting_queue(best_route->next_hop, true);
        bool request_deja_trimis = !queue_empty(packet_queue);

        struct packet_in_asteptare *packet_waiting = malloc(sizeof(struct packet_in_asteptare));
        DIE(!packet_waiting, "malloc packet_in_asteptare");
        packet_waiting->buf = malloc(len);
        DIE(!packet_waiting->buf, "malloc packet_waiting->buf");
        memcpy(packet_waiting->buf, buf, len);
        packet_waiting->lenght        = len;
        packet_waiting->next_hop_ip   = best_route->next_hop;
        packet_waiting->out_interface = best_route->interface;
        queue_enq(packet_queue, packet_waiting);

        if (!request_deja_trimis)
            trimite_arp_request(best_route->next_hop, best_route->interface);
        return;
    }

    get_interface_mac(best_route->interface, e_header->ethr_shost);
    memcpy(e_header->ethr_dhost, arp_entry->mac, 6);

    printf("[DEBUG] Trimit pachet dirijat pe interfata %d catre %s.\n",
            best_route->interface, inet_ntoa(*(struct in_addr*)&best_route->next_hop));
    send_to_link(len, buf, best_route->interface);
}

int main(int argc, char *argv[]) {
    char buf[MAX_PACKET_LEN];
    init(argv + 2, argc - 2);

    aloca_si_citeste_tabele(argv[1]);
    struct tree_node *root = construieste_trie_rutare();

    for (int i = 0; i < WAITING_BUCKETS; i++) {
        waiting[i] = NULL;
    }

    printf("[DEBUG] Router pornit. Astept pachete...\n");

    while (1) {
        int interface;
        size_t len;

        interface = recv_from_any_link(buf, &len);
        DIE(interface < 0, "recv_from_any_links");

        struct ether_hdr *e_header = (struct ether_hdr *)buf;
        uint16_t ethertype = ntohs(e_header->ethr_type);

        if (ethertype == 0x0806) {
            handle_arp(buf, interface);
            continue;
        }

        if (ethertype != 0x0800) {
            continue;
        }

        struct ip_hdr *ip_header = (struct ip_hdr *)(buf + sizeof(struct ether_hdr));
        printf("\n[DEBUG] --- Pachet IPv4 primit pe %d ---\n", interface);

        if (este_pachet_pentru_mine(ip_header)) {
            if (ip_header->proto == 1) {
                struct icmp_hdr *icmp = (struct icmp_hdr *)((char *)ip_header + ip_header->ihl * 4);
                if (icmp->mtype == 8) {
                    trimite_icmp_echo_reply(interface, e_header, ip_header, buf, len);
                }
            }
            continue;
        }

        if (!pachet_valid_checksum_si_ttl(ip_header, e_header, interface)) {
            continue;
        }

        proceseaza_si_trimite(root, buf, len, e_header, ip_header, interface);
    }

    free(tabel_rutare);
    free(arp_tablou);

    return 0;
}