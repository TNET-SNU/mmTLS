#define __MOS_CORE_

#include <string.h>
#include <netinet/ip.h>
#include <stdbool.h>

#include "ip_in.h"
#include "ip_out.h"
#include "tcp.h"
#include "mtcp_api.h"
#include "debug.h"
#include "mos_api.h"
#include "icmp.h"
#include "config.h"

#define ETH_P_IP_FRAG   0xF800
#define ETH_P_IPV6_FRAG 0xF6DD
#define DNS_PORT 443


/*----------------------------------------------------------------------------*/
inline void
FillInPacketIPContext (struct pkt_ctx *pctx, struct iphdr *iph, int ip_len)
{
	pctx->p.iph = iph;
	pctx->p.ip_len = ip_len;
	
	return;
}
/*----------------------------------------------------------------------------*/
inline int 
ProcessInIPv4Packet(mtcp_manager_t mtcp, struct pkt_ctx *pctx)
{
	bool release = false;
	int ret;
	struct mon_listener *walk;
	/* check and process IPv4 packets */
	struct iphdr* iph =
		(struct iphdr *)((char *)pctx->p.ethh + sizeof(struct ethhdr));
	struct udphdr *udph;
	int ip_len = ntohs(iph->tot_len);

	/* drop the packet shorter than ip header */
	if (ip_len < sizeof(struct iphdr)) {
		ret = ERROR;
		goto __return;
	}

	if (iph->version != IPVERSION ) {
		release = true;
		ret = FALSE;
		goto __return;
	}

	FillInPacketIPContext(pctx, iph, ip_len);

#if 0
	printf("dip: %d.%d.%d.%d\n",
			*(uint8_t *)&iph->daddr,
			*((uint8_t *)&iph->daddr + 1),
			*((uint8_t *)&iph->daddr + 2),
			*((uint8_t *)&iph->daddr + 3));
#endif

	/* callback for monitor raw socket */
	TAILQ_FOREACH(walk, &mtcp->monitors, link)
		if (walk->socket->socktype == MOS_SOCK_MONITOR_RAW) {
			if (ISSET_BPFFILTER(walk->raw_pkt_fcode) &&
				EVAL_BPFFILTER(walk->raw_pkt_fcode, (uint8_t *)pctx->p.ethh,
							   pctx->p.eth_len))
				HandleCallback(mtcp, MOS_NULL, walk->socket, MOS_SIDE_BOTH,
							   pctx, MOS_ON_PKT_IN);
			
		}
	
	/* if there is no MOS_SOCK_STREAM or MOS_SOCK_MONITOR_STREAM socket,
	   forward IP packet before reaching upper (transport) layer */
	if (mtcp->num_msp == 0 && mtcp->num_esp == 0) {
		if (pctx->forward) {
			ForwardIPPacket(mtcp, pctx);
		}
		return TRUE;
	}

#if 0 // already turned on offload by default
	if (ip_fast_csum(iph, iph->ihl)) {
		ret = ERROR;
		goto __return;
	}
#endif

	switch (iph->protocol) {
	  case IPPROTO_TCP:
		return ProcessInTCPPacket(mtcp, pctx);
	  case IPPROTO_UDP:
		udph = (struct udphdr *)((char *)iph + (pctx->p.iph->ihl << 2));
		if ((ntohs(udph->source) == DNS_PORT) ||
			(ntohs(udph->dest) == DNS_PORT))
			// printf("DNS detected\n");
			;
	  case IPPROTO_ICMP:
		// printf("ICMP detected\n");
		/* true when destined to me */
		if (ProcessICMPPacket(mtcp, pctx))
			return TRUE;
	  default:
		/* forward without any processing */
		if (!mtcp->num_msp || !pctx->forward)
			release = true;
		else {
			pctx->forward = 2;
			ForwardIPPacket(mtcp, pctx);
		}
		
		ret = FALSE;
		goto __return;
	}

__return:
	if (release && mtcp->iom->release_pkt)
		mtcp->iom->release_pkt(mtcp->ctx, pctx->p.in_ifidx,
				       (unsigned char *)pctx->p.ethh, pctx->p.eth_len);
	return ret;
}
/*----------------------------------------------------------------------------*/
