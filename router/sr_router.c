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
 * If we should forward IP packet, return true. If packet is destined for us, return false.
 *
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


void handle_ip_packet(struct sr_instance *sr, struct sr_if *interface, unsigned int len, uint8_t *packet) {
  /*check length of ip packet*/
  if(len < sizeof(struct sr_ip_hdr)) {
    return;
  }

  /*convert to ip header by stripping of ethernet header*/
  struct sr_ip_hdr *ip_hdr_info = (struct sr_ip_hdr *) (packet + sizeof(struct sr_ethernet_hdr));
  
  /*perform check sum*/ 
  uint16_t curr_sum = ip_hdr_info->ip_sum; 
  uint16_t new_sum = cksum((void *) ip_hdr_info, len); 

  if(curr_sum != new_sum) {
    /*drop packet if checksums dont match*/
    return;
  }

  if(should_forward_packet(sr->if_list, ip_hdr_info)) {
    /*forwarding logic*/
  }
  else {
    /*handle destination packet*/
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
  struct sr_if *named_interface = sr_get_interface(sr, interface);
  if(!named_interface) {
    return;
  }
  
  if(len < sizeof(struct sr_ethernet_hdr)) {
    fprintf(stderr, "Packet not correct size.\n");
    return;
  }
  
  uint16_t ethtype = ethertype(packet);
  
  /* got this casting from sr_utils.c in ethertype function */
  struct sr_ethernet_hdr *ether_hdr_info = (struct sr_ethernet_hdr *) packet;
  
  /* handle ip packet */
  if(ethtype == ethertype_ip) {
    handle_ip_packet(sr, named_interface, len - sizeof(struct sr_ethernet_hdr), packet);
  }

  /* handle arp packet */
  else if(ethtype == ethertype_arp) {

  }

}/* end sr_ForwardPacket */

