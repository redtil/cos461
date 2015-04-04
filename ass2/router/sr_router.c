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
    arptype(sr,packet,len,interface);
  }
  if(ethertype(packet) == ethertype_ip)
  {
    if(cksum(packet, len))
    {
      if("router's ip" == "dest ip" ){
        router_ip_same(sr,packet,len, interface);
      }
      else{
        router_ip_not_same(sr, packet, len,interface);
      }
    }
    else{
        /*drop packet*/
    }
  }
  }/* -- sr_handlepacket -- */

  void arptype(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
  {
    if(ntohs((sr_arp_hdr_t *)packet->ar_op)) == arp_op_request)
    {
      size_t n =  (sr_ethernet_hdr_t*)packet->ether-dhost;
      sr_ethernet_hdr_t *temp = malloc(sizeof((sr_ethernet_hdr_t*)packet->ether-dhost));
      sr_ethernet_hdr_t *dest = malloc(sizeof((sr_ethernet_hdr_t*)packet->ether-dhost));
   
      memcpy(temp, (sr_ethernet_hdr_t*)packet->ether-dhost, n);
      memcpy(dest, (sr_ethernet_hdr_t*)packet->ether-dhost, n);
      memcpy((sr_ethernet_hdr_t*)packet->ether-dhost, temp, n);


    }
    else {

    }
  }

  void router_ip_not_same(struct sr_instance* sr,
          uint8_t * packet/* lent */,
          unsigned int len,
          char* interface/* lent */)
  {
     //Decrement TTL by 1 and recompute checksum
     sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(packet);
     iphdr->ipttl--;
     if(iphdr->ipttl > 0)
     {
        //Find longest-match IP in routing table
        find_ip(sr, packet, len, interface);
     }
     else{
        
     }    
  }

  void router_find_ip(sr, packet, len, interface)
  {

    //find longest-match IP in routing table
    if(hit)
    {
        search_cache_MAC_addr(sr, packet, len, interface);
    }
    else{

    }
  }
  void search_cache_MAC_addr(sr, packet, len, interface)
  {
    //find MAC_ADD that corresponds to IP address
    if(hit)
    {
      //Forward the received frame out with new MAC address
        send_frame(sr, packet, len, interface);
    }
    else{
        //Send ARP request for desired next-hop IP

    }

  }


  /*void router_ip_same(struct sr_instance* sr,
          uint8_t * packet/* lent */
         /* unsigned int len,
          char* interface/* lent *
 /* {
    /*Check if the packet is an ICMP echo request w/ valid checksum*/
      /*if(!((cksum(packet, len)) && (ip_protocol(packet))))
    {
      //check if the packet contains TCP
      if()
      {
        //Port unreachable (type 3, code 3)
      }
      else{
          //drop packet
      }
    }

  }*/
