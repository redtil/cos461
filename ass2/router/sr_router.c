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
void send_icmp_host_unreach(struct sr_instance* sr, struct sr_arpreq *req)
{

}

 void make_arp_packet(struct sr_instance* sr, 
         uint8_t* packet,  struct sr_rt *ip_rt_match)
 {
    sr_arp_hdr_t* packet_arp_hdr = (sr_arp_hdr_t*)(packet+sizeof(sr_ethernet_hdr_t));
    sr_ethernet_hdr_t* packet_ethernet_hdr = (sr_ethernet_hdr_t*)(packet);
    packet_arp_hdr->ar_hrd = htons(1);
    packet_arp_hdr->ar_pro = htons(ethertype_ip);
    packet_arp_hdr->ar_hln = 6;
    packet_arp_hdr->ar_pln = WORD_BYTELEN;
    packet_arp_hdr->ar_op = htons(arp_op_request);
    struct sr_if* found_if = sr_get_interface(sr, ip_rt_match->interface);

    memcpy(packet_arp_hdr->ar_sha, found_if->addr, ETHER_ADDR_LEN); 
    memset(packet_arp_hdr->ar_tha, 0, ETHER_ADDR_LEN);
    

    packet_arp_hdr->ar_sip = found_if->ip;
    packet_arp_hdr->ar_tip = prev_arp_req->ip;

    for (i = 0; i < ETHER_ADDR_LEN; ++i)
      packet_ethernet_hdr->ether_dhost[i] = 0xff;
    memcpy(hdr->ether_shost, found_if->addr, ETHER_ADDR_LEN);
    packet_ethernet_hdr->ether_type = htons(ethertype_arp);
   
 }

 void send_arp_req(struct sr_instance* sr,
         unsigned int len, char* interface, 
         struct sr_arpreq * prev_arp_req,  struct sr_rt *ip_rt_match)
 {
    
 }
void handle_arpreq(struct sr_instance* sr, struct sr_arpreq *req){
 time_t now;
  if (time(&now)-req->sent > 1.0)
  {
    if(req->times_sent >= 5)
    {
      send_icmp_host_unreach(sr, req);
      arpreq_destroy(&(sr->cache), req);
    }
    else{
      struct sr_if* found_if = sr_get_interface(sr, ip_rt_match->interface);
      int numBytes_malloc = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
      uint8_t* packet = (uint8_t*)malloc(numBytes_malloc);
      make_arp_packet(sr, packet, ip_rt_match);
      sr_send_packet(sr,packet, numBytes_malloc, found_if->name );
      req->times_sent ++;  
      req->sent = time(&now);
    }
  }
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

void make_icmp_t3_packet(struct sr_instance* sr,
        uint8_t * packet/* lent */,uint8_t * newPacket,
       unsigned int len,
        char* interface/* lent */)
 {
  uint8_t temp[ETHER_ADDR_LEN];
  memcpy(newPacket, packet, sizeof(struct sr_ethernet_hdr));
  
  sr_ethernet_hdr_t *ether_hdr = (sr_ethernet_hdr_t*) newPacket;
  memcpy(temp, ether_hdr->ether_shost, ETHER_ADDR_LEN);
  memcpy(ether_hdr->ether_shost, ether_hdr->ether_dhost, ETHER_ADDR_LEN);
  memcpy(ether_hdr->ether_dhost, temp1, ETHER_ADDR_LEN);

  sr_ip_hdr_t *ip_hdr= (sr_ip_hdr_t*)(newPacket+sizeof(sr_ethernet_hdr_t));
  sr_icmp_t3_hdr_t *icmp_t3_hdr = (sr_icmp_t3_hdr_t*)(newPacket+sizeof(sr_ethernet_hdr_t)+sizeof(sr_icmp_t3_hdr_t));
  ip_hdr->ip_ttl++;


  ip_hdr->ip_v = 4;
  ip_hdr->ip_hl = 5;
  ip_hdr->ip_tos = 0;
  ip_hdr->ip_id = 0;
  ip_hdr->ip_off = 0;
  ip_hdr->ip_ttl = 64;
  ip_hdr->ip_p = IPPROTO_ICMP;   

  assert(icmphdr); 
  icmphdr->icmp_type = type;
  icmphdr->icmp_code = code;
  icmphdr->icmp_unused = 0;

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
 * by sr_vns_comm.c that means do NOT free either (signified by "lent" comment).  
 * Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/
 void send_icmp_port_unreach(struct sr_instance* sr,
        uint8_t * packet/* lent */,
       unsigned int len,
        char* interface/* lent */)
 {
    int numBytes_malloc = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
    uint8_t* newPacket = (uint8_t*)malloc(numBytes_malloc);
    make_icmp_t3_packet(sr, packet, newPacket, len, interface);
    sr_send_packet(sr,newPacket, numBytes_malloc, interface);


  
    struct ip *sendip = (struct ip*) (sendpacket + sizeof(struct sr_ethernet_hdr));
    struct icmp_hdr *sendicmp = (struct icmp_hdr*) (sendip + 1);
    memcpy(sendpacket, packet, sizeof(struct sr_ethernet_hdr));
    ether_addr_swap((struct sr_ethernet_hdr*) sendpacket);
    ippacket->ip_ttl += 1;      
    icmp_prefill(sendip, sendicmp, ICMP_UNREACH, ICMP_PORT_UNREACH);
    icmp_specfill(sendip, sendicmp, (ippacket->ip_dst).s_addr, (ippacket->ip_src).s_addr, 
              (uint8_t*) ippacket, iphdr_bytelen + ICMPDAT_LEN);
    if (sr_send_packet(sr, sendpacket, sendlen, interface)) 
      fprintf(stderr, "Packet sending (in response to packet addressed to interface %s) failed\n", interface);
    free(sendpacket);
    

 }
 int router_ip_check(struct sr_instance* sr,
        uint8_t * packet/* lent */,
       unsigned int len,
        char* interface/* lent */)
  {
    sr_ip_hdr_t * ip_hdr = (sr_ip_hdr_t *)(packet+sizeof(sr_ethernet_hdr_t));
    struct sr_if *cur = sr->if_list;
    struct sr_if *next;
    for(;next!= NULL; cur = next)
    {
      if(cur->ip == ip_hdr->ar_tip)
        return 1;
      else
        next = cur->next;
    } 
    return 0;
  }

void send_icmp_echo_reply(struct sr_instance* sr,
        uint8_t * packet/* lent */,
       unsigned int len,
        char* interface/* lent */)
{
  sr_ip_hdr_t * ip_hdr = (sr_ip_hdr_t *)(packet+sizeof(sr_ethernet_hdr_t));
  sr_icmp_hdr_t * icmp_hdr = (sr_icmp_hdr_t *)(packet+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t));

  uint32_t temp = iphdr->ip_src;
  iphdr->ip_src = iphdr->ip_dst;
  iphdr->ip_dst = temp;

  sr_send_packet(sr, packet, len, interface);
}

 void router_ip_same(struct sr_instance* sr,
        uint8_t * packet/* lent */,
       unsigned int len,
        char* interface/* lent */)
  {
    sr_ip_hdr_t * ip_hdr = (sr_ip_hdr_t *)(packet+sizeof(sr_ethernet_hdr_t));
    sr_icmp_hdr_t * icmp_hdr = (sr_icmp_hdr_t *)(packet+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t));
    uint16_t cp = icmp_hdr->icmp_sum;
    icmp_hdr->icmp_sum = 0;
    if((icmp_hdr->icmp_type == 0)&& (cksum(icmp_hdr, ntohs((ip_hdr->ip_len) - (ip_hdr->ip_hl)))==cp))
    {
      send_icmp_echo_reply(sr,packet,len,interface);
    }
    else
    {
     if(ip_hdr->ip_p == 0x11 || ip_hdr->ip_p == 0x06)
     {
        send_icmp_port_unreach(sr, packet, len, interface);
     } 
     else{
      printf("packet dropped \n");
     }
      
    }
  }

void find_ip_rt(sr, packet, len, interface)
  {
    sr_ip_hdr_t * ip_hdr = (sr_ip_hdr_t *)(packet+sizeof(sr_ethernet_hdr_t));
    struct sr_rt *cur = sr->routing_table; 
    struct sr_rt* next;  
    struct sr_rt* bestMatch = 0;
    uint8_t *ip_dst_8 = (uint8_t*) &(ip_hdr->ip_dst);
    uint8_t *rt_ip_8 = (uint8_t*) &(cur->dest).s_addr;
    uint8_t *rt_mask_8 = (uint8_t*) &(cur->mask).s_addr;
    uint8_t rt_ip_mask;
    int i = 0;
    int numBytes = 0;
    int fndDiscr = 0;
    int longestMatch = 0;
    for (; next != NULL; cur = next)
    {
      for(i; i< 4; i++)
      {
        rt_ip_mask = (*ip_dst_8) & (*rt_mask_8);
        if(!rt_ip_mask)
        {
          break;
        }
        if(rt_ip_mask != *rt_ip_8)
        {
          fndDiscr = 1;
          break;
        }
        rt_ip_8++;
        rt_mask_8++;
        ip_dst_8++;  
        numBytes++;
      }

      if(fndDiscr)
        {
          fndDiscr = 0;
        }
      else if (numBytes> longestMatch )
      {
        longestMatch = numBytes;
        bestMatch = cur;
      }

      numBytes = 0;

      next = cur->next;
    }
    return bestMatch;   
  }
  void send_icmp_dest_unreach(struct sr_instance* sr,
          uint8_t * packet/* lent */,
          unsigned int len,
          char* interface/* lent */)
  {

  }
  void send_icmp_time_exceeded(struct sr_instance* sr,
          uint8_t * packet/* lent */,
          unsigned int len,
          char* interface/* lent */)
  {

  }
 
  void send_to_MAC_addr(struct sr_instance* sr,
         struct sr_rt *ip_rt_match,
          struct sr_arpentry *findCacheEntry, unsigned int len, char* interface
          )
 {
   struct sr_if* found_if = sr_get_interface(sr, ip_rt_match->interface);
   memcpy(((struct sr_ethernet_hdr *) packet)->ether_shost, found_if->addr, ETHER_ADDR_LEN);
   memcpy(((struct sr_ethernet_hdr *) packet)->ether_dhost, findCacheEntry->mac, ETHER_ADDR_LEN);  
   sr_send_packet(sr, packet, len, found_if->name);
 }

struct sr_arpreq *prev_arp_req_search(struct sr_instance* sr,
         uint8_t * packet/* lent */, unsigned int len,
          char* interface, struct sr_rt *ip_rt_match)
 {
  struct sr_arpreq * cur = (sr->cache).requests;
  struct sr_arpreq * next;
  for(; cur!= NULL; cur = next)
  {
    if(cur->ip == (ip_rt_match->gw).s_addr)
      return cur;
    next = cur->next;
  }
  return 0;

 }

  void router_ip_not_same(struct sr_instance* sr,
          uint8_t * packet/* lent */,
          unsigned int len,
          char* interface/* lent */)
  {
     /*Decrement TTL by 1 and recompute checksum*/
     struct sr_arpentry *fndCacheEntry;
     sr_ip_hdr_t * ip_hdr = (sr_ip_hdr_t *)(packet+sizeof(sr_ethernet_hdr_t));
     ip_hdr->ip_ttl--;
     uint16_t cp = ip_hdr->ip_sum;
     ip_hdr->ip_sum = 0;

     if(iphdr->ip_ttl > 0 && cksum(ip_hdr, ntohs(ip_hdr->ip_len) )== cp)
     {
        struct sr_rt *ip_rt_match = find_ip_rt(sr, packet, len, interface);

        /*Find longest-match IP in routing table*/
        if(ip_rt_match)
        {
          if(fndCacheEntry = sr_arpcache_lookup(&(sr->cache), (ip_rt_match->gw).s_addr))
          {
            send_to_MAC_addr(sr, ip_rt_match, fndCacheEntry, len, interface);
          }
          else{
            struct sr_arpreq * req = sr_arpcache_queuereq(&(sr->cache),
                           (ip_rt_match->gw).s_addr,
                           packet,              
                           len,
                           ip_rt_match->interface);

            handle_arpreq(sr, req);
          }
        }
        else
        {
          send_icmp_dest_unreach(sr,packet, len, interface);
        }
     }
     else{
        send_icmp_time_exceeded(sr, packet, len, interface);
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
    	((sr_ethernet_hdr_t*)packet)->ether_shost, ETHER_ADDR_LEN);
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
  sr_ip_hdr_t * ip_hdr = (sr_ip_hdr_t *)(packet+sizeof(sr_ethernet_hdr_t));
  if(ethertype(packet)== ethertype_arp)
  {
	  printf("it's an arp. \n");
    arptype(sr,packet,len,interface);
  }
  else if(ethertype(packet) == ethertype_ip)
  {
	/*printf("it's ip. \n");*/
	  
	/*printf("packet old check sum value: %d \n", ip_hdr->ip_sum);*/
	uint16_t cp = ip_hdr->ip_sum;
	ip_hdr->ip_sum = 0;
	/*printf("packet zeroed out check sum value: %d \n", ip_hdr->ip_sum);
	printf("check sum value: %d \n", cksum(ip_hdr,ntohs(ip_hdr->ip_len)));
	printf("packet check sum value: %d \n", cp);*/
    if(cksum(ip_hdr, ntohs(ip_hdr->ip_len) )== cp)
    {
	     /*printf("the checksum works. \n");*/
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

  

  
 

 
 


