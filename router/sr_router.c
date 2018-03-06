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
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

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

void sr_init(struct sr_instance* sr)
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


/**
 * Returns the length of the IP mask (network prefix length).
 */
static int mask_length(uint32_t subnet_mask) {
  int len = 0;
  while(subnet_mask) {
    len += subnet_mask & 1;
    subnet_mask >>= 1;
  }
  return len;
}


/**
 * If we should forward IP packet, return true. If packet is destined for us, return false.
 */
bool should_forward_packet(struct sr_if *interface, struct sr_ip_hdr *ip_hdr_info) {
  struct sr_if *trav = interface;
  uint32_t ip_dst = ip_hdr_info->ip_dst;

  while(trav) {
    if(ip_dst == trav->ip) {
      return false;
    }
    trav = trav->next;
  }

  return true;
}


/**
  * Finds the longest prefix match in the routing table.
  */
struct sr_rt *longest_prefix_match(struct sr_instance *sr, uint32_t ip_dst) {

  struct sr_rt *table = sr->routing_table;
  struct sr_rt *ret = 0;
  int max_len = -1;
  
  while(table) {
    uint32_t mask = table->mask.s_addr;
    int mask_len = mask_length(mask);

    /* destination ip & subnet mask should be the same as interface ip & mask*/
    if(mask_len > max_len && ((ip_dst & mask) == (table->dest.s_addr & mask))) {
        max_len = mask_len;
        ret = table;
    }
    table = table->next;
  }

  return ret;
}


void handle_arp_packet(struct sr_instance *sr, char* interface, unsigned int len, uint8_t *packet){
	sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
  printf("arp packet from interface: ");
	printf(interface);
  printf("\n");

	if(ntohs(arp_hdr->ar_op)==arp_op_request){
		struct sr_if *interf = sr_get_interface(sr,interface);
		if(interf){
			sr_arp_reply(sr,interf,arp_hdr->ar_sha,arp_hdr->ar_sip);
		}
	}

	else if(ntohs(arp_hdr->ar_op)==arp_op_reply){
		struct sr_if *interf = sr_get_interface(sr,interface);
		if(interf){
			struct sr_arpreq *req = sr_arpcache_insert(&sr->cache,arp_hdr->ar_sha,arp_hdr->ar_sip);
			if(req){
				struct sr_packet* ip_packet = req->packets;
				while(ip_packet){
					struct sr_ethernet_hdr *ether_hdr = (struct sr_ethernet_hdr* )(ip_packet->buf);
					memcpy(ether_hdr->ether_shost, interf->addr, 6);
					memcpy(ether_hdr->ether_dhost, arp_hdr->ar_sha, 6);
					sr_send_packet(sr, ip_packet->buf, ip_packet->len, ip_packet->iface);
					ip_packet = ip_packet->next;
				}
			}
		}
	}
}


/**
  * Handles an incoming IP packet.
  */
void handle_ip_packet(struct sr_instance *sr, char* interface, unsigned int len, uint8_t *packet) {
  /*check length of ip packet*/
	if(len - sizeof(struct sr_ethernet_hdr) < sizeof(struct sr_ip_hdr)) {
    /* drop packet */
    return;
  }

  /* get the ethernet header*/
  struct sr_ethernet_hdr *eth_hdr_info = (struct sr_ethernet_hdr *) (packet);

  /*get the ip header by stripping off ethernet header*/
  struct sr_ip_hdr *ip_hdr_info = (struct sr_ip_hdr *) (packet + sizeof(struct sr_ethernet_hdr));
  
  /*get the check sum*/ 
  uint16_t curr_sum = ip_hdr_info->ip_sum; 
  /*need to zero out check sum before recomputing*/
  ip_hdr_info->ip_sum = 0;
  /*recompute checksum*/
  uint16_t new_sum = cksum((void *) ip_hdr_info, sizeof(struct sr_ip_hdr)); 

  /*drop packet if checksums dont match*/
  if(curr_sum != new_sum) {
    /* drop packet */
    return;
  }

  /*forwarding logic*/
  if(should_forward_packet(sr->if_list, ip_hdr_info)) {
    /*check if ttl == 0*/
    if (ip_hdr_info->ip_ttl == 0) {
      /* send ICMP with type 11, code 0 */
      send_ICMP_packet(sr, packet, interface, len, 11, 0);
      return;
    }

    /*decrement ttl and recompute check sum*/
    ip_hdr_info->ip_ttl--;
    ip_hdr_info->ip_sum = 0;
    uint16_t send_sum = cksum((void *) ip_hdr_info, sizeof(struct sr_ip_hdr));
    ip_hdr_info->ip_sum = send_sum;

    /*prefix matching*/
    print_addr_ip_int(ip_hdr_info->ip_dst);
    struct sr_rt *rt_entry = longest_prefix_match(sr, ip_hdr_info->ip_dst);

    if (rt_entry == NULL) {
      /* no matching entry in routing table */
      /* send ICMP with type 3, code 0 */
      printf("No matching entry in routing table\n");
      send_ICMP_packet(sr, packet, interface, len, 3, 0);
    }

    /* use ARP to set destination ethernet address */
    struct sr_arpentry *arp_entry = sr_arpcache_lookup(&sr->cache, rt_entry->dest.s_addr);

    if (arp_entry != NULL) {
      /* set ethernet source and destination address */
      printf("In arp cache \n");
      struct sr_if *interf = sr_get_interface(sr, rt_entry->interface);

      int i;
      for (i = 0; i < ETHER_ADDR_LEN; ++i) {
        eth_hdr_info->ether_shost[i] = interf->addr[i];
        eth_hdr_info->ether_dhost[i] = arp_entry->mac[i];
      }
      /* send packet to next hop router */
      sr_send_packet(sr, packet, len, rt_entry->interface); 
    }
   
    else {
      /* ARP entry not in cache -- populate ARP cache */
      printf("Not in arp cache \n");
      struct sr_arpreq *req = sr_arpcache_queuereq(&sr->cache, ip_hdr_info->ip_dst, packet, len, rt_entry->interface);
      handle_arpreq(&sr, req);
    }
  }

  else {
    /* handle destination packet */
    struct sr_ip_hdr *ip_hdr = (struct sr_ip_hdr *)(packet + sizeof(struct sr_ethernet_hdr));

    if (ip_protocol(ip_hdr) == ip_protocol_icmp) {
      /* IP paylaod is ICMP message */
      struct sr_icmp_hdr *icmp_hdr = (struct sr_icmp_hdr *)(packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr));

      if (icmp_hdr->icmp_type == 8 && icmp_hdr->icmp_code == 0) {
        /* ICMP message is echo request */ 
        send_ICMP_packet(sr, packet, interface, len, 0, 0);

        /*
        uint16_t sent_sum = icmp_hdr->icmp_sum;
        icmp_hdr->icmp_sum = 0;
        if (sent_sum == cksum((void *) icmp_hdr, sizeof(struct sr_icmp_hdr))) {
          
        }
        */
      }
    }
  }
}


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

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);
  
  if(len < sizeof(struct sr_ethernet_hdr)) {
    /* drop packet */
    return;
  }
  uint16_t ethtype = ethertype(packet);
  
  /* handle ip packet */
  if(ethtype == ethertype_ip) {
    handle_ip_packet(sr, interface, len, packet);
  }

  /* handle arp packet */
  else if(ethtype == ethertype_arp) {
    handle_arp_packet(sr, interface, len, packet);
  }
}/* end sr_ForwardPacket */


/**
  * Sends ICMP packet to source sender
  */
void send_ICMP_packet(struct sr_instance* sr, uint8_t* packet, char* iface, 
                      unsigned int len, uint8_t icmp_type, uint8_t icmp_code) {
  /* get the ethernet header */
  struct sr_ethernet_hdr *eth_hdr_info = (struct sr_ethernet_hdr *)(packet);

  /* get the ip header */
  struct sr_ip_hdr *ip_hdr_info = (struct sr_ip_hdr *)(packet + sizeof(struct sr_ethernet_hdr));

  /* get the ICMP header */
  struct sr_icmp_hdr *icmp_hdr = (struct sr_icmp_hdr *)(packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr));

  struct sr_if *interf = sr_get_interface(sr, iface);

  /* update the IP src and dst */
  ip_hdr_info->ip_dst = ip_hdr_info->ip_src;
  ip_hdr_info->ip_src = interf->ip;
  ip_hdr_info->ip_sum = 0;
  ip_hdr_info->ip_sum = cksum((void *)(ip_hdr_info), sizeof(struct sr_ip_hdr));

  /* update the ethernet src and dst */
  int i;
  for (i = 0; i < ETHER_ADDR_LEN; i++) {
    eth_hdr_info->ether_dhost[i] = eth_hdr_info->ether_shost[i];
    eth_hdr_info->ether_shost[i] = interf->addr[i];
  }

  /* get the payload */
  struct sr_icmp_hdr payload;
  payload.icmp_type = icmp_type;
  payload.icmp_code = icmp_code;
  payload.icmp_sum = 0;

  /* replace old payload with ICMP payload */
  memcpy(icmp_hdr, &payload, sizeof(struct sr_icmp_hdr));

  /* calculate new ICMP checksum */
  icmp_hdr->icmp_sum = cksum((void *)(icmp_hdr), sizeof(struct sr_icmp_hdr));

  sr_send_packet(sr, packet, len, iface);
}
