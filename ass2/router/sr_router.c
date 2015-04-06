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
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/* TODO: Add constant definitions here... */

/* TODO: Add helper functions here... */

/* See pseudo-code in sr_arpcache.h */
void handle_arpreq(struct sr_instance* sr, struct sr_arpreq *req){
/*
   The handle_arpreq() function is a function you should write, and it should
   handle sending ARP requests if necessary:
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
}

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
    
    /* TODO: (opt) Add initialization code here */

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
 * by sr_vns_comm.c that means do NOT free either (signified by "lent" comment).  
 * Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/
 int router_ip_check(struct sr_instance* sr,
        uint8_t * packet/* lent */,
       unsigned int len,
        char* interface/* lent */)
  {
    struct sr_if *cur = sr->if_list;
    struct sr_if *next;
    for(;next!= NULL; cur = next)
    {
      if(cur->ip == ((sr_arp_hdr_t *)packet)->ar_tip)
        return 1;
      else
        next = cur->next;
    }
    return 0;
  }
void send_echo_reply(struct sr_instance* sr,
        uint8_t * packet/* lent */,
       unsigned int len,
        char* interface/* lent */)
{
  

}
 void router_ip_same(struct sr_instance* sr,
        uint8_t * packet/* lent */,
       unsigned int len,
        char* interface/* lent */)
  {
    if((((sr_icmp_hdr_t*)packet)->icmp_type == 0)&& (cksum(packet, len)==((sr_ip_hdr_t*)packet)->ip_sum))
    {
      send_echo_reply(sr,packet,len,interface);
    }
    else
    {

    }
  }

  
   void search_cache_MAC_addr(sr, packet, len, interface)
  {
    /*find MAC_ADD that corresponds to IP address*/
    /*if()
    {*/
      /*Forward the received frame out with new MAC address*/
        /*send_frame(sr, packet, len, interface);*/
   /* }*/
    /*else*/
        /*Send ARP request for desired next-hop IP*/

    /*}*/

  }

void router_find_ip(sr, packet, len, interface)
  {

    /*find longest-match IP in routing table*/
    /*if()
    {
        search_cache_MAC_addr(sr, packet, len, interface);
    }
    else{

    }*/
  }

void router_ip_not_same(struct sr_instance* sr,
          uint8_t * packet/* lent */,
          unsigned int len,
          char* interface/* lent */)
  {
     /*Decrement TTL by 1 and recompute checksum*/
     sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(packet);
     iphdr->ip_ttl--;
     if(iphdr->ip_ttl > 0)
     {
        /*Find longest-match IP in routing table*/
        router_find_ip(sr, packet, len, interface);
     }
     else{
        
     }    
  }

void send_queued_IP_packets(struct sr_instance* sr,
      uint8_t * packet/* lent */,
      unsigned int len,
      char* interface/* lent */){
struct sr_arpreq *cur = sr->cache.requests; 
struct sr_arpreq * next;	
for (; next != NULL; cur = next )
{
if(cur->ip == ((sr_arp_hdr_t *)packet)->ar_sip)
{
	memcpy(((sr_ethernet_hdr_t*)packet)->ether_dhost, 	
	((sr_ethernet_hdr_t*)packet)->ether_shost, 	    		ETHER_ADDR_LEN);
      memcpy(((sr_ethernet_hdr_t*)packet)->ether_shost, ((struct sr_if*) interface)->addr,ETHER_ADDR_LEN);
	sr_send_packet(sr, packet, len, interface);
}
next = cur->next;
}

}

 void arptype(struct sr_instance* sr,
      uint8_t * packet/* lent */,
      unsigned int len,
      char* interface/* lent */)
{
  print_hdr_eth(packet);

  if(ntohs(((sr_arp_hdr_t *)packet)->ar_op) == arp_op_request)
  {
    /*look at arp_reply_fill*/
    memcpy(((sr_ethernet_hdr_t*)packet)->ether_dhost, ((sr_ethernet_hdr_t*)packet)->ether_shost,ETHER_ADDR_LEN);
    memcpy(((sr_ethernet_hdr_t*)packet)->ether_shost, ((struct sr_if*)interface)->addr,ETHER_ADDR_LEN);

    ((sr_arp_hdr_t *)packet)->ar_tip = ((sr_arp_hdr_t *)packet)->ar_sip ;
    ((sr_arp_hdr_t *)packet)->ar_sip = ((struct sr_if*)interface)-> ip;
    memcpy(((sr_arp_hdr_t *)packet)->ar_tha, ((sr_arp_hdr_t*)packet)->ar_sha, ETHER_ADDR_LEN);
    memcpy(((sr_arp_hdr_t *)packet)->ar_sha, ((struct sr_if *)interface)->addr, ETHER_ADDR_LEN);

    ((sr_arp_hdr_t*)packet)->ar_op = arp_op_reply;
    sr_send_packet(sr, packet, len, interface);
  }
  else {
  	sr_arpcache_insert(&(sr->cache), ((sr_arp_hdr_t*)packet)->ar_sha, ((sr_arp_hdr_t*)packet)->ar_sip); 
  	send_queued_IP_packets(sr,packet,len, interface);

  }
}
 
 void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{

  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d\n",len);

  if(ethertype(packet)== ethertype_arp)
  {
	  printf("it's an arp. \n");
    arptype(sr,packet,len,interface);
  }
  else if(ethertype(packet) == ethertype_ip)
  {
	  printf("it's ip. \n");
	  
	printf("packet old check sum value: %d \n", ((sr_ip_hdr_t*) packet)->ip_sum);
	uint16_t cp = ((sr_ip_hdr_t*) packet)->ip_sum;
	((sr_ip_hdr_t*) packet)->ip_sum= 0;
printf("packet zeroed out check sum value: %d \n", ((sr_ip_hdr_t*) packet)->ip_sum);
printf("check sum value: %d \n", cksum((sr_ip_hdr_t*)packet,((sr_ip_hdr_t*)packet)->ip_len));
	printf("packet check sum value: %d \n", cp);
    if(cksum((sr_ip_hdr_t*)packet, ntohs(((sr_ip_hdr_t*)packet)->ip_len)) == cp)
    {
	printf("the checksum works. \n");
      if(router_ip_check(sr, packet, len, interface)){
        router_ip_same(sr,packet,len, interface);
      }
      else{
        router_ip_not_same(sr, packet, len,interface);
      }
    }
      else
     {
        printf("packet dropped \n");
     }
  }
   
  }/* -- sr_handlepacket -- */

  

  
 

 
 


