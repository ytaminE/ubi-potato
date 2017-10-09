#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <string.h>
#include "sr_arpcache.h"
#include "sr_router.h"
#include "sr_if.h"
#include "sr_protocol.h"
#include "sr_rt.h"
#include "sr_utils.h"

/* 
  This function gets called every second. For each request sent out, we keep
  checking whether we should resend an request or destroy the arp request.
  See the comments in the header file for an idea of what it should look like.
*/
void sr_arpcache_sweepreqs(struct sr_instance *sr) { 
    /* Fill this in */
    /* TODO: Change*/
    struct sr_arpreq *arp_req = sr->cache.requests;
    struct sr_arpreq *arp_req_next = NULL;
    while (arp_req != NULL) {
		arp_req_next = arp_req->next;
        handle_arpreq(arp_req, sr);
		arp_req = arp_req_next;
    }
    return;
}

/* function handle_arpreq(req):
    if difftime(now, req->sent) > 1.0
        if req->times_sent >= 5:
            send icmp host unreachable to source addr of all pkts waiting
            on this request
            arpreq_destroy(req)
        else:
            send arp request
            req->sent = now
            req->times_sent++ 
*/

void handle_arpreq(struct sr_arpreq *arp_req, struct sr_instance *sr) {
    fprintf(stderr, "---------Start handling arp request----------\n");
    
    struct sr_arpcache *cache = &(sr->cache);

    if(difftime(time(0), arp_req->sent) > 1.0) {
        if(arp_req->times_sent >=5 ) {
            /*List of pkts waiting on this req to finish*/
            struct sr_packet *packet = arp_req->packets;

            /* Start sending ICMP host unreachable to source addr of all pkts waiting*/                
            while(packet != NULL) {
                struct sr_if *packet_if = sr_get_interface(sr, packet->iface);
                uint8_t *eth_frame = packet->buf;

                /* Extract ethernet header and ip header */
                sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)eth_frame;
                sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)((char *)eth_frame+ sizeof(sr_ethernet_hdr_t));
                
                /* Get target MAC and IP address */
                uint8_t *tar_mac = eth_hdr->ether_shost;
                uint32_t tar_ip = ip_hdr->ip_src;
                
                /*struct sr_rt* target = (struct sr_rt*)sr_lpm(sr->routing_table, requests->ip);*/
                struct sr_rt* lpm = sr_lpm(sr, tar_ip);        
                struct sr_if *lpm_if = sr_get_interface(sr, lpm->interface);    
                
                
                /* Construct ICMP headerr */
                uint8_t *icmp = (uint8_t *)malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));

                /* Construct the ethernet header */                
                sr_ethernet_hdr_t *icmp_eth_hdr = (sr_ethernet_hdr_t *)icmp;
                memcpy(icmp_eth_hdr->ether_dhost, tar_mac, ETHER_ADDR_LEN);
                memcpy(icmp_eth_hdr->ether_shost, lpm_if->addr, ETHER_ADDR_LEN);                
                icmp_eth_hdr->ether_type = eth_hdr->ether_type;
                
                /* Construct the IP header */
                sr_ip_hdr_t *icmp_ip_hdr = (sr_ip_hdr_t *)((char *)icmp + sizeof(sr_ethernet_hdr_t));
				icmp_ip_hdr->ip_hl = ip_hdr->ip_hl;	
				icmp_ip_hdr->ip_v = ip_hdr->ip_v;
                icmp_ip_hdr->ip_tos = ip_hdr->ip_tos;

                /* TODO: Why 56? ????????????????????*/
                icmp_ip_hdr->ip_len = htons(56);
                icmp_ip_hdr->ip_id = ip_hdr->ip_id;
                icmp_ip_hdr->ip_off = htons(0b0100000000000000);
                icmp_ip_hdr->ip_ttl = 64;
                icmp_ip_hdr->ip_p = ip_protocol_icmp;
                icmp_ip_hdr->ip_src = packet_if->ip; 
                icmp_ip_hdr->ip_dst = tar_ip;
				icmp_ip_hdr->ip_sum = 0;
                icmp_ip_hdr->ip_sum = cksum(icmp_ip_hdr, sizeof(sr_ip_hdr_t));

                /* Construct the ICMP header */
                sr_icmp_t3_hdr_t *icmp_hdr = (sr_icmp_t3_hdr_t *)((char *)icmp + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
                
                /* Host unreachalbe */
                icmp_hdr->icmp_type = 3;
                icmp_hdr->icmp_code = 1;
                icmp_hdr->unused = 0;
                icmp_hdr->next_mtu = 0;
                memcpy(icmp_hdr->data, ip_hdr, ICMP_DATA_SIZE);
				icmp_hdr->icmp_sum = 0;
                icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(sr_icmp_t3_hdr_t));

                struct sr_arpentry *entry = sr_arpcache_lookup(cache, tar_ip);

                if(entry != NULL) {
                    sr_send_packet(sr, icmp, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t), lpm->interface);
                    
                    free(icmp);
                } else {
                    struct sr_arpreq *arp_queue_req = sr_arpcache_queuereq(cache, tar_ip, icmp, 
                        sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t),
                        lpm->interface);
                    handle_arpreq(arp_queue_req, sr);
                }
                packet = packet->next;
            }
            sr_arpreq_destroy(cache, arp_req);            
        } else {
            sr_broadcast_arpreq(sr, arp_req);
            arp_req->sent = time(0);
            arp_req->times_sent++;
        }
    }
    fprintf(stderr, "---------Stop handling arp request---------\n");
    return;
}


  void sr_broadcast_arpreq(struct sr_instance* sr, struct sr_arpreq *req) {
    struct sr_if *broad_if = sr_get_interface(sr, req->packets->iface);    
    uint8_t *arp_req_hdr = (uint8_t *)malloc(sizeof(sr_ethernet_hdr_t)+sizeof(sr_arp_hdr_t));
    
    /* Construct the ethernet header */
    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)arp_req_hdr;

    memcpy(eth_hdr->ether_shost, broad_if->addr, ETHER_ADDR_LEN);
    /* ARP requests are sent to broadcast MAC address(ff-ff-ff-ff-ff-ff)*/
	int i;
    for (i = 0; i < ETHER_ADDR_LEN; ++i) {
        eth_hdr->ether_dhost[i] = 255;          
    }
    eth_hdr->ether_type = htons(ethertype_arp);
    
    /* Construct the ARP header */
    sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)((char *)arp_req_hdr + sizeof(sr_ethernet_hdr_t));
    
    arp_hdr->ar_hrd = htons(arp_hrd_ethernet);
    arp_hdr->ar_pro = htons(ethertype_ip);
    arp_hdr->ar_hln = ETHER_ADDR_LEN;
    arp_hdr->ar_pln = 4;
    arp_hdr->ar_op = htons(arp_op_request);
    memcpy(arp_hdr->ar_sha, broad_if->addr, ETHER_ADDR_LEN);
    arp_hdr->ar_sip = broad_if->ip;
    
    for (i = 0; i < ETHER_ADDR_LEN; ++i) {
        arp_hdr->ar_tha[i] = 255;
    }    
  
    arp_hdr->ar_tip = req->ip;
    printf("Strat sending arp packet request packet\n");    
    sr_send_packet(sr, arp_req_hdr, sizeof(sr_ethernet_hdr_t)+sizeof(sr_arp_hdr_t), broad_if->name);  
    free(arp_req_hdr);
    return;
  }

/* You should not need to touch the rest of this code. */

/* Checks if an IP->MAC mapping is in the cache. IP is in network byte order.
   You must free the returned structure if it is not NULL. */
struct sr_arpentry *sr_arpcache_lookup(struct sr_arpcache *cache, uint32_t ip) {
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpentry *entry = NULL, *copy = NULL;
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if ((cache->entries[i].valid) && (cache->entries[i].ip == ip)) {
            entry = &(cache->entries[i]);
        }
    }
    
    /* Must return a copy b/c another thread could jump in and modify
       table after we return. */
    if (entry) {
        copy = (struct sr_arpentry *) malloc(sizeof(struct sr_arpentry));
        memcpy(copy, entry, sizeof(struct sr_arpentry));
    }
        
    pthread_mutex_unlock(&(cache->lock));
    
    return copy;
}

/* Adds an ARP request to the ARP request queue. If the request is already on
   the queue, adds the packet to the linked list of packets for this sr_arpreq
   that corresponds to this ARP request. You should free the passed *packet.
   
   A pointer to the ARP request is returned; it should not be freed. The caller
   can remove the ARP request from the queue by calling sr_arpreq_destroy. */
struct sr_arpreq *sr_arpcache_queuereq(struct sr_arpcache *cache,
                                       uint32_t ip,
                                       uint8_t *packet,           /* borrowed */
                                       unsigned int packet_len,
                                       char *iface)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req;
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {
            break;
        }
    }
    
    /* If the IP wasn't found, add it */
    if (!req) {
        req = (struct sr_arpreq *) calloc(1, sizeof(struct sr_arpreq));
        req->ip = ip;
        req->next = cache->requests;
        cache->requests = req;
    }
    
    /* Add the packet to the list of packets for this request */
    if (packet && packet_len && iface) {
        struct sr_packet *new_pkt = (struct sr_packet *)malloc(sizeof(struct sr_packet));
        
        new_pkt->buf = (uint8_t *)malloc(packet_len);
        memcpy(new_pkt->buf, packet, packet_len);
        new_pkt->len = packet_len;
		new_pkt->iface = (char *)malloc(sr_IFACE_NAMELEN);
        strncpy(new_pkt->iface, iface, sr_IFACE_NAMELEN);
        new_pkt->next = req->packets;
        req->packets = new_pkt;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* This method performs two functions:
   1) Looks up this IP in the request queue. If it is found, returns a pointer
      to the sr_arpreq with this IP. Otherwise, returns NULL.
   2) Inserts this IP to MAC mapping in the cache, and marks it valid. */
struct sr_arpreq *sr_arpcache_insert(struct sr_arpcache *cache,
                                     unsigned char *mac,
                                     uint32_t ip)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req, *prev = NULL, *next = NULL; 
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {            
            if (prev) {
                next = req->next;
                prev->next = next;
            } 
            else {
                next = req->next;
                cache->requests = next;
            }
            
            break;
        }
        prev = req;
    }
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if (!(cache->entries[i].valid))
            break;
    }
    
    if (i != SR_ARPCACHE_SZ) {
        memcpy(cache->entries[i].mac, mac, 6);
        cache->entries[i].ip = ip;
        cache->entries[i].added = time(NULL);
        cache->entries[i].valid = 1;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* Frees all memory associated with this arp request entry. If this arp request
   entry is on the arp request queue, it is removed from the queue. */
void sr_arpreq_destroy(struct sr_arpcache *cache, struct sr_arpreq *entry) {
    pthread_mutex_lock(&(cache->lock));
    
    if (entry) {
        struct sr_arpreq *req, *prev = NULL, *next = NULL; 
        for (req = cache->requests; req != NULL; req = req->next) {
            if (req == entry) {                
                if (prev) {
                    next = req->next;
                    prev->next = next;
                } 
                else {
                    next = req->next;
                    cache->requests = next;
                }
                
                break;
            }
            prev = req;
        }
        
        struct sr_packet *pkt, *nxt;
        
        for (pkt = entry->packets; pkt; pkt = nxt) {
            nxt = pkt->next;
            if (pkt->buf)
                free(pkt->buf);
            if (pkt->iface)
                free(pkt->iface);
            free(pkt);
        }
        
        free(entry);
    }
    
    pthread_mutex_unlock(&(cache->lock));
}

/* Prints out the ARP table. */
void sr_arpcache_dump(struct sr_arpcache *cache) {
    fprintf(stderr, "\nMAC            IP         ADDED                      VALID\n");
    fprintf(stderr, "-----------------------------------------------------------\n");
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        struct sr_arpentry *cur = &(cache->entries[i]);
        unsigned char *mac = cur->mac;
        fprintf(stderr, "%.1x%.1x%.1x%.1x%.1x%.1x   %.8x   %.24s   %d\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ntohl(cur->ip), ctime(&(cur->added)), cur->valid);
    }
    
    fprintf(stderr, "\n");
}

/* Initialize table + table lock. Returns 0 on success. */
int sr_arpcache_init(struct sr_arpcache *cache) {  
    /* Seed RNG to kick out a random entry if all entries full. */
    srand(time(NULL));
    
    /* Invalidate all entries */
    memset(cache->entries, 0, sizeof(cache->entries));
    cache->requests = NULL;
    
    /* Acquire mutex lock */
    pthread_mutexattr_init(&(cache->attr));
    pthread_mutexattr_settype(&(cache->attr), PTHREAD_MUTEX_RECURSIVE);
    int success = pthread_mutex_init(&(cache->lock), &(cache->attr));
    
    return success;
}

/* Destroys table + table lock. Returns 0 on success. */
int sr_arpcache_destroy(struct sr_arpcache *cache) {
    return pthread_mutex_destroy(&(cache->lock)) && pthread_mutexattr_destroy(&(cache->attr));
}

/* Thread which sweeps through the cache and invalidates entries that were added
   more than SR_ARPCACHE_TO seconds ago. */
void *sr_arpcache_timeout(void *sr_ptr) {
    struct sr_instance *sr = sr_ptr;
    struct sr_arpcache *cache = &(sr->cache);
    
    while (1) {
        sleep(1.0);
        
        pthread_mutex_lock(&(cache->lock));
    
        time_t curtime = time(NULL);
        
        int i;    
        for (i = 0; i < SR_ARPCACHE_SZ; i++) {
            if ((cache->entries[i].valid) && (difftime(curtime,cache->entries[i].added) > SR_ARPCACHE_TO)) {
                cache->entries[i].valid = 0;
            }
        }
        
        sr_arpcache_sweepreqs(sr);

        pthread_mutex_unlock(&(cache->lock));
    }
    
    return NULL;
}

