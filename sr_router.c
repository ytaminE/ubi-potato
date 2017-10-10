/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance *sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);

    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance *sr,
                     uint8_t *packet /* lent */,
                     unsigned int len,
                     char *interface /* lent */)
{
    /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(interface);

    printf("*** -> Received packet of length %d \n", len);

    /* fill in code here */

    /* Sanity-check the packet (meets the minimum length)*/
    if (len < sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arp_hdr))
    {
        fprintf(stderr, "packet length is smaller the ethernet size. Drop it!\n");
        return;
    }

    /* Handle the ARP or IP packet*/
    if (ethertype(packet) == ethertype_arp)
    {
        printf("This is an ARP packet\n");
        print_hdr_eth(packet);
        sr_handle_arppacket(sr, packet, len, interface);
        return;
    }
    else if (ethertype(packet) == ethertype_ip)
    {
        printf("This is an IP packet\n");
        print_hdr_eth(packet);
        sr_handle_ippacket(sr, packet, len, interface);
        return;
    }
    else
    {
        fprintf(stderr, "Unknonw packet");
        return;
    }

} /* end sr_ForwardPacket */

/* TODO:*/
void sr_handle_arppacket(struct sr_instance *sr, uint8_t *packet /* lent */, unsigned int len, char *interface /* lent */)
{
    printf("------------------------------------------\n");

    printf("Start handling ARP packet\n");
    /* Extract ethernet header */
    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;

    /* Extract ARP header */
    sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)((unsigned char *)packet + sizeof(sr_ethernet_hdr_t));

    /* Extract ARP opcode (command) */
    unsigned short ar_op = ntohs(arp_hdr->ar_op);

    struct sr_if *sr_interface = sr_get_interface(sr, interface);
    if (!sr_interface)
    {
        printf("This interface doesn't exisit.");
        return;
    }

    /* Handle the ARP request */
    if (ar_op == arp_op_request)
    {
        printf("This is an ARP request\n");

        /* Create the ethernet header */
        /*uint8_t *eth_reply = (uint8_t *)malloc(sizeof(sr_ethernet_hdr_t)+sizeof(sr_arp_hdr_t)); */
        sr_ethernet_hdr_t *eth_reply = (uint8_t *)malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
        memcpy(eth_reply->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);
        memcpy(eth_reply->ether_shost, sr_interface->addr, ETHER_ADDR_LEN);
        eth_reply->ether_type = eth_hdr->ether_type;

        /* Create the ARP reply header */
        sr_arp_hdr_t *arp_reply = (sr_arp_hdr_t *)((unsigned char *)eth_reply + sizeof(sr_ethernet_hdr_t));
        arp_reply->ar_hrd = arp_hdr->ar_hrd;
        arp_reply->ar_hrd = arp_hdr->ar_hrd;
        arp_reply->ar_pro = arp_hdr->ar_pro;
        arp_reply->ar_hln = arp_hdr->ar_hln;
        arp_reply->ar_pln = arp_hdr->ar_pln;
        arp_reply->ar_op = htons(arp_op_reply);
        arp_reply->ar_tip = arp_hdr->ar_sip;
        arp_reply->ar_sip = sr_interface->ip;
        memcpy(arp_reply->ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN);
        memcpy(arp_reply->ar_sha, sr_interface->addr, ETHER_ADDR_LEN);

        /*Start sending ARP reply */
        printf("The ARP reply to send is: \n");
        print_hdr_eth(eth_reply);
        print_hdr_arp(arp_reply);
        sr_send_packet(sr, eth_reply, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t), sr_interface->name);
        free(eth_reply);
        return;
    }
    else if (ar_op == arp_op_reply)
    {

        /* Handle the ARP reply */
        printf("This is an ARP reply\n");
        printf("The ARP received is: \n");
        print_hdr_eth(eth_hdr);
        printf("Start handling the ARP reply");

        /* Cache */
        struct sr_arpcache *cache = &(sr->cache);
        struct sr_arpreq *arp_request = sr_arpcache_insert(cache, arp_hdr->ar_sha, arp_hdr->ar_sip);

        if (arp_request)
        {
            struct sr_packet *packet = arp_request->packets;
            /* Go through all the packets in the queue. */
            while (packet != NULL)
            {
                uint8_t *eth_frame = packet->buf;
                unsigned int len = packet->len;
                sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)eth_frame;
                struct sr_if *packet_if = sr_get_interface(sr, packet->iface);
                /* source host is the address of the interface */
                memcpy(eth_hdr->ether_shost, packet_if->addr, ETHER_ADDR_LEN);
                /* destination host is the packet's sender's address */
                memcpy(eth_hdr->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
                print_hdrs(eth_frame, len);
                sr_send_packet(sr, eth_frame, len, packet_if->name);
                packet = packet->next;
            }
            sr_arpreq_destroy(cache, arp_request);
        }
    }
    else
    {
        printf("Unknown ARP packet");
    }
    return;
}

void sr_handle_ippacket(struct sr_instance *sr, uint8_t *packet /* lent */, unsigned int len, char *interface /* lent */)
{

    fprintf(stderr, "Start handling IP packet\n");

    /* Extract ethernet header */
    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;

    /* Extract IP header */
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)((unsigned char *)packet + sizeof(sr_ethernet_hdr_t));

    /* Examine the checksum */
    uint16_t ip_sum_temp = ip_hdr->ip_sum;
    ip_hdr->ip_sum = 0;

    if (!cksum(ip_hdr, sizeof(sr_ip_hdr_t)) == ip_sum_temp)
    {
        printf("The checksum in this IP packet is not correct!");
        return;
    }

    ip_hdr->ip_sum = ip_sum_temp;

    /* ARP cachee */
    struct sr_arpcache *sr_arp_cache = &sr->cache;
    struct sr_if *dst_if = sr_get_router_if(sr, ip_hdr->ip_dst);
    struct sr_if *cur_if = sr_get_interface(sr, interface);

    /*     struct sr_if *sr_iface = sr_get_router_if(sr, ip_hdr->ip_dst);
    struct sr_if *sr_con_if = sr_get_interface(sr, interface);
 */
    /* Check the TTL */
    if (ip_hdr->ip_ttl <= 1)
    {
        /* TODO:Change */
        /* Construct the ICMP packet */
        int ICMP_LENGTH = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
        uint8_t *icmp_packet = (uint8_t *)malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));

        /* Construct the Ethernet header */
        sr_ethernet_hdr_t *new_eth_hdr = (sr_ethernet_hdr_t *)icmp_packet;
        memcpy(new_eth_hdr->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);
        memcpy(new_eth_hdr->ether_shost, cur_if->addr, ETHER_ADDR_LEN);
        new_eth_hdr->ether_type = eth_hdr->ether_type;

        /* Construct the IP header */
        sr_ip_hdr_t *new_ip_hdr = (sr_ip_hdr_t *)((unsigned char *)icmp_packet + sizeof(sr_ethernet_hdr_t));
        new_ip_hdr->ip_hl = ip_hdr->ip_hl;
        new_ip_hdr->ip_v = ip_hdr->ip_v;
        new_ip_hdr->ip_tos = ip_hdr->ip_tos;
        new_ip_hdr->ip_len = htons(56);
        new_ip_hdr->ip_id = 0;
        new_ip_hdr->ip_off = htons(0b0100000000000000);
        new_ip_hdr->ip_ttl = 64;
        new_ip_hdr->ip_p = ip_protocol_icmp;
        new_ip_hdr->ip_src = cur_if->ip;
        new_ip_hdr->ip_dst = ip_hdr->ip_src;
        new_ip_hdr->ip_sum = 0;
        uint16_t new_ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
        new_ip_hdr->ip_sum = new_ip_sum;
        /* Construct ICMP header with type 11 code 0 */
        sr_icmp_t3_hdr_t *icmp_hdr = (sr_icmp_t3_hdr_t *)((unsigned char *)icmp_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
        icmp_hdr->icmp_type = 11;
        icmp_hdr->icmp_code = 0;
        icmp_hdr->unused = 0;
        icmp_hdr->next_mtu = 0;
        memcpy(icmp_hdr->data, ip_hdr, ICMP_DATA_SIZE);
        icmp_hdr->icmp_sum = 0;
        uint16_t new_icmp_sum = cksum(icmp_hdr, sizeof(sr_icmp_t3_hdr_t));
        icmp_hdr->icmp_sum = new_icmp_sum;
        /* Send ICMP packet */
        struct sr_arpentry *entry = sr_arpcache_lookup(sr_arp_cache, ip_hdr->ip_src);
        if (entry != NULL)
        {
            sr_send_packet(sr, icmp_packet, ICMP_LENGTH, cur_if->name);
            free(icmp_packet);
        }
        else
        {
            struct sr_arpreq *arp_req = sr_arpcache_queuereq(sr_arp_cache,
                                                             ip_hdr->ip_src, icmp_packet, ICMP_LENGTH, cur_if->name);
            handle_arpreq(arp_req, sr);
        }
        return;
    }

    uint8_t ip_p = ip_hdr->ip_p;

    /* %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% */

    /* If the packet is sent to self, meaning the ip is sent to the router */
    /* TODO: ????????why dst_if? */
    if (dst_if)
    {
        /* Check the IP protocol */
        if (ip_p == ip_protocol_icmp)
        {
            /* Get the icmp header */
            sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)((unsigned char *)packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
            /* TODO: why type 8? */
            if (icmp_hdr->icmp_type == 8)
            {

                struct sr_rt *lpm_rt = sr_lpm(sr, ip_hdr->ip_src);

                if (lpm_rt)
                {

                    /* Check the ARP cache */
                    struct sr_arpentry *entry = sr_arpcache_lookup(&sr->cache, lpm_rt->gw.s_addr);
                    struct sr_if *lpm_if = sr_get_interface(sr, lpm_rt->interface);

                    if (entry != NULL)
                    {
                        /* If hit, send the ICMP reply */

                        /* Ethernet header */
                        memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);
                        memcpy(eth_hdr->ether_shost, lpm_if->addr, ETHER_ADDR_LEN);

                        /* IP header */
                        ip_hdr->ip_off = htons(0b0100000000000000);
                        ip_hdr->ip_ttl = 100;
                        uint32_t temp = ip_hdr->ip_src;
                        ip_hdr->ip_src = ip_hdr->ip_dst;
                        ip_hdr->ip_dst = temp;
                        ip_hdr->ip_sum = 0;
                        uint16_t new_ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
                        ip_hdr->ip_sum = new_ip_sum;

                        /* ICMP header */
                        /* TODO: why not sizeof(sr_icmp_hdr_t) */
                        unsigned int icmp_size = len - sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t);
                        icmp_hdr->icmp_type = 0;
                        icmp_hdr->icmp_code = 0;
                        icmp_hdr->icmp_sum = 0;
                        uint16_t new_icmp_sum = cksum(icmp_hdr, icmp_size);
                        icmp_hdr->icmp_sum = new_icmp_sum;

                        /* Send icmp echo reply */
                        sr_send_packet(sr, packet, len, lpm_if->name);
                        return;
                    }
                    else
                    {
                        /* No hit, cache it to the queue and send arp request */
                        /* Add reply to the ARP queue */
                        memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);
                        memcpy(eth_hdr->ether_shost, cur_if->addr, ETHER_ADDR_LEN);

                        /* IP header */
                        ip_hdr->ip_off = htons(0b0100000000000000);
                        ip_hdr->ip_ttl = 100;
                        uint32_t temp = ip_hdr->ip_src;
                        ip_hdr->ip_src = ip_hdr->ip_dst;
                        ip_hdr->ip_dst = temp;
                        ip_hdr->ip_sum = 0;
                        uint16_t new_ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
                        ip_hdr->ip_sum = new_ip_sum;

                        /* ICMP header */
                        unsigned int icmp_size = len - sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t);
                        icmp_hdr->icmp_type = 0;
                        icmp_hdr->icmp_code = 0;
                        icmp_hdr->icmp_sum = 0;
                        icmp_hdr->icmp_sum = cksum(icmp_hdr, icmp_size);

                        struct sr_arpreq *arp_req = sr_arpcache_queuereq(sr_arp_cache, ip_hdr->ip_dst, packet, len, lpm_if->name);
                        /* Send ARP request, which is a broadcast */
                        handle_arpreq(arp_req, sr);
                        return;
                    }
                }
                else
                {
                    fprintf(stderr, "No longest prefix found\n");
                    return;
                }
            }
            else
            {
                fprintf(stderr, "Not an ICMP type 8 request!\n");
                return;
            }
        }
        else
        {
            /* Handle the TCP/UDP request */
            fprintf(stderr, "*** -> Received TCP/UDP request!\n");

            /* Do LPM on the routing table */
            /* Check the routing table and see if the incoming ip matches the routing table ip, and find LPM router entry */
            struct sr_rt *lpm_rt = sr_lpm(sr, ip_hdr->ip_src);
            if (lpm_rt)
            {
                /* check ARP cache */
                struct sr_arpentry *entry = sr_arpcache_lookup(&sr->cache, lpm_rt->gw.s_addr);
                struct sr_if *lpm_if = sr_get_interface(sr, lpm_rt->interface);

                /* Send ICMP port unreachable */
                if (entry != NULL)
                {
                    /* Construct the ICMP packet */
                    int ICMP_LENGTH = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
                    uint8_t *icmp_packet = (uint8_t *)malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));

                    /* Construct the Ethernet header */
                    sr_ethernet_hdr_t *new_eth_hdr = (sr_ethernet_hdr_t *)icmp_packet;
                    memcpy(new_eth_hdr->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);
                    memcpy(new_eth_hdr->ether_shost, dst_if->addr, ETHER_ADDR_LEN);
                    new_eth_hdr->ether_type = eth_hdr->ether_type;

                    /* Construct the IP header */
                    sr_ip_hdr_t *new_ip_hdr = (sr_ip_hdr_t *)((unsigned char *)icmp_packet + sizeof(sr_ethernet_hdr_t));
                    new_ip_hdr->ip_hl = ip_hdr->ip_hl;
                    new_ip_hdr->ip_v = ip_hdr->ip_v;
                    new_ip_hdr->ip_tos = ip_hdr->ip_tos;
                    new_ip_hdr->ip_len = htons(56);
                    new_ip_hdr->ip_id = 0;
                    new_ip_hdr->ip_off = htons(0b0100000000000000);
                    new_ip_hdr->ip_ttl = 64;
                    new_ip_hdr->ip_p = ip_protocol_icmp;
                    new_ip_hdr->ip_src = dst_if->ip;
                    new_ip_hdr->ip_dst = ip_hdr->ip_src;
                    new_ip_hdr->ip_sum = cksum(new_ip_hdr, sizeof(sr_ip_hdr_t));

                    /* Construct ICMP header with type 3 code 3 */
                    sr_icmp_t3_hdr_t *icmp_hdr = (sr_icmp_t3_hdr_t *)((unsigned char *)icmp_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
                    icmp_hdr->icmp_type = 3;
                    icmp_hdr->icmp_code = 3;
                    icmp_hdr->unused = 0;
                    icmp_hdr->next_mtu = 0;
                    memcpy(icmp_hdr->data, ip_hdr, ICMP_DATA_SIZE);
                    icmp_hdr->icmp_sum = 0;
                    icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(sr_icmp_t3_hdr_t));

                    /* Send ICMP packet */
                    sr_send_packet(sr, icmp_packet, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t), lpm_if->name);
                    free(icmp_packet);
                    return;
                }
                else
                {
                    /* Construct the ICMP packet */
                    int ICMP_LENGTH = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
                    uint8_t *icmp_packet = (uint8_t *)malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));

                    /* Construct the Ethernet header */
                    sr_ethernet_hdr_t *new_eth_hdr = (sr_ethernet_hdr_t *)icmp_packet;
                    memcpy(new_eth_hdr->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);
                    memcpy(new_eth_hdr->ether_shost, dst_if->addr, ETHER_ADDR_LEN);
                    new_eth_hdr->ether_type = eth_hdr->ether_type;

                    /* Construct the IP header */
                    sr_ip_hdr_t *new_ip_hdr = (sr_ip_hdr_t *)((unsigned char *)icmp_packet + sizeof(sr_ethernet_hdr_t));
                    new_ip_hdr->ip_hl = ip_hdr->ip_hl;
                    new_ip_hdr->ip_v = ip_hdr->ip_v;
                    new_ip_hdr->ip_tos = ip_hdr->ip_tos;
                    new_ip_hdr->ip_len = htons(56);
                    new_ip_hdr->ip_id = 0;
                    new_ip_hdr->ip_off = htons(0b0100000000000000);
                    new_ip_hdr->ip_ttl = 64;
                    new_ip_hdr->ip_p = ip_protocol_icmp;
                    new_ip_hdr->ip_src = dst_if->ip;
                    new_ip_hdr->ip_dst = ip_hdr->ip_src;
                    new_ip_hdr->ip_sum = 0;
                    uint16_t new_ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
                    new_ip_hdr->ip_sum = new_ip_sum;

                    /* Construct ICMP header with type 3 code 3 */
                    sr_icmp_t3_hdr_t *icmp_hdr = (sr_icmp_t3_hdr_t *)((unsigned char *)icmp_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
                    icmp_hdr->icmp_type = 3;
                    icmp_hdr->icmp_code = 3;
                    icmp_hdr->unused = 0;
                    icmp_hdr->next_mtu = 0;
                    memcpy(icmp_hdr->data, ip_hdr, ICMP_DATA_SIZE);
                    icmp_hdr->icmp_sum = 0;
                    uint16_t new_icmp_sum = cksum(icmp_hdr, sizeof(sr_ip_hdr_t));
                    icmp_hdr->icmp_sum = new_icmp_sum;

                    struct sr_arpreq *arp_req = sr_arpcache_queuereq(sr_arp_cache, ip_hdr->ip_src, icmp_packet,
                                                                     sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t), lpm_if->name);
                    handle_arpreq(arp_req, sr);
                    return;
                }
            }
            else
            {
                fprintf(stderr, "No longest prefix found\n");
                return;
            }
        }
    }
    else
    {
        /* Fail to get the interface for the destinantion IP*/
        /* Sanity check*/
        if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t))
        {
            fprintf(stderr, "The length of the packet is less than the required number");
            return;
        }
        /* LPM */
        struct sr_rt *lpm_rt = sr_lpm(sr, ip_hdr->ip_dst);
        if (lpm_rt)
        {
            /* check ARP cache */
            struct sr_if *lpm_if = sr_get_interface(sr, lpm_rt->interface);
            struct sr_arpentry *entry = sr_arpcache_lookup(&sr->cache, lpm_rt->gw.s_addr);

            if (entry)
            {
                ip_hdr->ip_ttl--;
                /* Re-caculate the checksum */
                ip_hdr->ip_sum = 0;
                uint16_t new_ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
                ip_hdr->ip_sum = new_ip_sum;

                memcpy(eth_hdr->ether_shost, lpm_if->addr, ETHER_ADDR_LEN);
                memcpy(eth_hdr->ether_dhost, entry->mac, ETHER_ADDR_LEN);
                sr_send_packet(sr, packet, len, lpm_if->name);
                /* free the entry */
                free(entry);
                return;
            }
            else
            {
                /* Not hit */

                ip_hdr->ip_ttl--;
                /* Re-caculate the checksum */
                ip_hdr->ip_sum = 0;
                uint16_t new_ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
                ip_hdr->ip_sum = new_ip_sum;

                struct sr_arpreq *arp_req = sr_arpcache_queuereq(sr_arp_cache, ip_hdr->ip_dst, packet, len, lpm_if->name);
                /* Send ARP broadcast */
                handle_arpreq(arp_req, sr);
                return;
            }
        }
        else
        {
            /* No LPM */
            /* Send ICMP net unreachable */
            struct sr_rt *lpm_rt = sr_lpm(sr, ip_hdr->ip_src);

            if (lpm_rt)
            {
                /* check ARP cache */
                struct sr_if *lpm_if = sr_get_interface(sr, lpm_rt->interface);
                struct sr_arpentry *entry = sr_arpcache_lookup(&sr->cache, lpm_rt->gw.s_addr);

                if (entry)
                {
                    /* Construct the ICMP packet */
                    int ICMP_LENGTH = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
                    uint8_t *icmp_packet = (uint8_t *)malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));

                    /* Construct the Ethernet header */
                    sr_ethernet_hdr_t *new_eth_hdr = (sr_ethernet_hdr_t *)icmp_packet;
                    memcpy(new_eth_hdr->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);
                    memcpy(new_eth_hdr->ether_shost, lpm_if->addr, ETHER_ADDR_LEN);
                    new_eth_hdr->ether_type = eth_hdr->ether_type;

                    /* Construct the IP header */
                    sr_ip_hdr_t *new_ip_hdr = (sr_ip_hdr_t *)((unsigned char *)icmp_packet + sizeof(sr_ethernet_hdr_t));
                    new_ip_hdr->ip_hl = ip_hdr->ip_hl;
                    new_ip_hdr->ip_v = ip_hdr->ip_v;
                    new_ip_hdr->ip_tos = ip_hdr->ip_tos;
                    new_ip_hdr->ip_len = htons(56);
                    new_ip_hdr->ip_id = 0;
                    new_ip_hdr->ip_off = htons(0b0100000000000000);
                    new_ip_hdr->ip_ttl = 64;
                    new_ip_hdr->ip_p = ip_protocol_icmp;
                    new_ip_hdr->ip_src = lpm_if->ip;
                    new_ip_hdr->ip_dst = ip_hdr->ip_src;
                    new_ip_hdr->ip_sum = 0;
                    uint16_t new_ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
                    new_ip_hdr->ip_sum = new_ip_sum;

                    /* Construct ICMP header with type 3 code 3 */
                    sr_icmp_t3_hdr_t *icmp_hdr = (sr_icmp_t3_hdr_t *)((unsigned char *)icmp_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
                    icmp_hdr->icmp_type = 3;
                    icmp_hdr->icmp_code = 0;
                    icmp_hdr->unused = 0;
                    icmp_hdr->next_mtu = 0;
                    memcpy(icmp_hdr->data, ip_hdr, ICMP_DATA_SIZE);
                    icmp_hdr->icmp_sum = 0;
                    uint16_t new_icmp_sum = cksum(icmp_hdr, sizeof(sr_ip_hdr_t));
                    icmp_hdr->icmp_sum = new_icmp_sum;

                    sr_send_packet(sr, icmp_packet, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t), lpm_if->name);
                    free(icmp_packet);
                    return;
                }
                else
                {
                    int ICMP_LENGTH = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
                    uint8_t *icmp_packet = (uint8_t *)malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));

                    /* Construct the Ethernet header */
                    sr_ethernet_hdr_t *new_eth_hdr = (sr_ethernet_hdr_t *)icmp_packet;
                    memcpy(new_eth_hdr->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);
                    memcpy(new_eth_hdr->ether_shost, lpm_if->addr, ETHER_ADDR_LEN);
                    new_eth_hdr->ether_type = eth_hdr->ether_type;

                    /* Construct the IP header */
                    sr_ip_hdr_t *new_ip_hdr = (sr_ip_hdr_t *)((unsigned char *)icmp_packet + sizeof(sr_ethernet_hdr_t));
                    new_ip_hdr->ip_hl = ip_hdr->ip_hl;
                    new_ip_hdr->ip_v = ip_hdr->ip_v;
                    new_ip_hdr->ip_tos = ip_hdr->ip_tos;
                    new_ip_hdr->ip_len = htons(56);
                    new_ip_hdr->ip_id = 0;
                    new_ip_hdr->ip_off = htons(0b0100000000000000);
                    new_ip_hdr->ip_ttl = 64;
                    new_ip_hdr->ip_p = ip_protocol_icmp;
                    new_ip_hdr->ip_src = lpm_if->ip;
                    new_ip_hdr->ip_dst = ip_hdr->ip_src;
                    new_ip_hdr->ip_sum = 0;
                    uint16_t new_ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
                    new_ip_hdr->ip_sum = new_ip_sum;

                    /* Construct ICMP header with type 3 code 3 */
                    sr_icmp_t3_hdr_t *icmp_hdr = (sr_icmp_t3_hdr_t *)((unsigned char *)icmp_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
                    icmp_hdr->icmp_type = 3;
                    icmp_hdr->icmp_code = 0;
                    icmp_hdr->unused = 0;
                    icmp_hdr->next_mtu = 0;
                    memcpy(icmp_hdr->data, ip_hdr, ICMP_DATA_SIZE);
                    icmp_hdr->icmp_sum = 0;
                    uint16_t new_icmp_sum = cksum(icmp_hdr, sizeof(sr_ip_hdr_t));
                    icmp_hdr->icmp_sum = new_icmp_sum;
                    struct sr_arpreq *arp_req = sr_arpcache_queuereq(sr_arp_cache, ip_hdr->ip_src, icmp_packet,
                                                                     sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t), lpm_if->name);
                    /* Send ARP broadcast */
                    handle_arpreq(arp_req, sr);
                    return;
                }
            }
            else
            {
                fprintf(stderr, "No longest prefix found\n");
                return;
            }
        }
    }
    return;
}

/* %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% */
/* Find the longest prefix match */
/* TODO: Change */
struct sr_rt *sr_lpm(struct sr_instance *sr, uint32_t ip_dst)
{

    struct sr_rt *routing_table = sr->routing_table;
    uint32_t len = 0;
    struct sr_rt *lpm_rt = NULL; /*sr->routing_table;*/

    while (routing_table)
    {
        if ((ip_dst & routing_table->mask.s_addr) == (routing_table->dest.s_addr & routing_table->mask.s_addr))
        {
            if (len < routing_table->mask.s_addr)
            {
                len = routing_table->mask.s_addr;
                lpm_rt = routing_table;
            }
        }
        routing_table = routing_table->next;
    }
    return lpm_rt;
}
/* get the possible interface from router */
struct sr_if *sr_get_router_if(struct sr_instance *sr, uint32_t ip)
{
    struct sr_if *iface_list = 0;
    iface_list = sr->if_list; /* Get a list of interfaces */
    /* Loop through the interface list until reaching the same ip */
    while (iface_list)
    {
        if (iface_list->ip == ip)
        {
            return iface_list;
        }
        iface_list = iface_list->next;
    }
    return 0;
}
/* %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% */