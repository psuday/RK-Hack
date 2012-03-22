/*
 * Adapted from /sys/netinet/ip_icmp.c
 *
 * This is a small example to show where to place a trigger on 
 * a certain icmp payload. This doesn't actually do anything really
 * useful :)
 *
 * Again, this was all written for educational purposes only. 
 *
 */


#include "replace/opt_ipsec.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/mbuf.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/kernel.h>
#include <sys/sysctl.h>
#include <sys/proc.h>

#include <net/if.h>
#include <net/route.h>

#define _IP_VHL
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/in_var.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip_var.h>
#include <netinet/icmp_var.h>

#ifdef IPSEC
#include <netinet6/ipsec.h>
#include <netkey/key.h>
#endif

#include "../config.h"
#include "icmp.h"

#include "replace/faith.h"
#if defined(NFAITH) && NFAITH > 0
#include <net/if_types.h>
#endif

#include "util.h"
#include "exec.h"

extern struct   icmpstat icmpstat;
extern int      icmpmaskrepl;
extern int      drop_redirect;
extern int      log_redirect;
extern int      icmpbmcastecho;

extern void	icmp_reflect __P((struct mbuf *));
extern void	icmp_send __P((struct mbuf *, struct mbuf *));
extern int	ip_next_mtu __P((int, int));

extern struct protosw inetsw[];

extern struct sockaddr_in icmpsrc;
extern struct sockaddr_in icmpdst;
extern struct sockaddr_in icmpgw;

void trigger_test(char *);

/* 
 * Trigger to call when an icmp packet with the specified
 * payload is received.
 */

void
trigger_test(char *payload)
{

    mod_debug("Got %s\n",payload);    

}

/*
 * Process a received ICMP message.
 *
 * Taken from /sys/netinet/ip_icmp.c with alterations
 */

void
new_icmp_input(register struct mbuf *m, int off, int proto)
{
	int hlen = off;
	register struct icmp *icp;
	register struct ip *ip = mtod(m, struct ip *);
	int icmplen = ip->ip_len;
	register int i;
	struct in_ifaddr *ia;
	void (*ctlfunc) __P((int, struct sockaddr *, void *));
	int code;

	/*
	 * Locate icmp structure in mbuf, and check
	 * that not corrupted and of at least minimum length.
	 */
#ifdef ICMPPRINTFS
	if (icmpprintfs) {
		char buf[4 * sizeof "123"];
		strcpy(buf, inet_ntoa(ip->ip_src));
		printf("icmp_input from %s to %s, len %d\n",
		       buf, inet_ntoa(ip->ip_dst), icmplen);
	}
#endif
	if (icmplen < ICMP_MINLEN) {
		icmpstat.icps_tooshort++;
		goto freeit;
	}
	i = hlen + min(icmplen, ICMP_ADVLENMIN);
	if (m->m_len < i && (m = m_pullup(m, i)) == 0)  {
		icmpstat.icps_tooshort++;
		return;
	}
	ip = mtod(m, struct ip *);
	m->m_len -= hlen;
	m->m_data += hlen;
	icp = mtod(m, struct icmp *);
	if (in_cksum(m, icmplen)) {
		icmpstat.icps_checksum++;
		goto freeit;
	}
	m->m_len += hlen;
	m->m_data -= hlen;

#if defined(NFAITH) && 0 < NFAITH
	if (m->m_pkthdr.rcvif && m->m_pkthdr.rcvif->if_type == IFT_FAITH) {
		/*
		 * Deliver very specific ICMP type only.
		 */
		switch (icp->icmp_type) {
		case ICMP_UNREACH:
		case ICMP_TIMXCEED:
			break;
		default:
			goto freeit;
		}
	}
#endif

#ifdef ICMPPRINTFS
	if (icmpprintfs)
		printf("icmp_input, type %d code %d\n", icp->icmp_type,
		    icp->icmp_code);
#endif

#ifdef IPSEC
	/* drop it if it does not match the policy */
	/* XXX Is there meaning of check in here ? */
	if (ipsec4_in_reject(m, NULL)) {
		ipsecstat.in_polvio++;
		goto freeit;
	}
#endif

	/*
	 * Message type specific processing.
	 */
	if (icp->icmp_type > ICMP_MAXTYPE)
		goto raw;
	icmpstat.icps_inhist[icp->icmp_type]++;
	code = icp->icmp_code;
	switch (icp->icmp_type) {

	case ICMP_UNREACH:
		switch (code) {
			case ICMP_UNREACH_NET:
			case ICMP_UNREACH_HOST:
			case ICMP_UNREACH_SRCFAIL:
			case ICMP_UNREACH_NET_UNKNOWN:
			case ICMP_UNREACH_HOST_UNKNOWN:
			case ICMP_UNREACH_ISOLATED:
			case ICMP_UNREACH_TOSNET:
			case ICMP_UNREACH_TOSHOST:
			case ICMP_UNREACH_HOST_PRECEDENCE:
			case ICMP_UNREACH_PRECEDENCE_CUTOFF:
				code = PRC_UNREACH_NET;
				break;

			case ICMP_UNREACH_NEEDFRAG:
				code = PRC_MSGSIZE;
				break;

			/*
			 * RFC 1122, Sections 3.2.2.1 and 4.2.3.9.
			 * Treat subcodes 2,3 as immediate RST
			 */
			case ICMP_UNREACH_PROTOCOL:
			case ICMP_UNREACH_PORT:
				code = PRC_UNREACH_PORT;
				break;

			case ICMP_UNREACH_NET_PROHIB:
			case ICMP_UNREACH_HOST_PROHIB:
			case ICMP_UNREACH_FILTER_PROHIB:
				code = PRC_UNREACH_ADMIN_PROHIB;
				break;

			default:
				goto badcode;
		}
		goto deliver;

	case ICMP_TIMXCEED:
		if (code > 1)
			goto badcode;
		code += PRC_TIMXCEED_INTRANS;
		goto deliver;

	case ICMP_PARAMPROB:
		if (code > 1)
			goto badcode;
		code = PRC_PARAMPROB;
		goto deliver;

	case ICMP_SOURCEQUENCH:
		if (code)
			goto badcode;
		code = PRC_QUENCH;
	deliver:
		/*
		 * Problem with datagram; advise higher level routines.
		 */
		if (icmplen < ICMP_ADVLENMIN || icmplen < ICMP_ADVLEN(icp) ||
		    IP_VHL_HL(icp->icmp_ip.ip_vhl) < (sizeof(struct ip) >> 2)) {
			icmpstat.icps_badlen++;
			goto freeit;
		}
		NTOHS(icp->icmp_ip.ip_len);
		/* Discard ICMP's in response to multicast packets */
		if (IN_MULTICAST(ntohl(icp->icmp_ip.ip_dst.s_addr)))
			goto badcode;
#ifdef ICMPPRINTFS
		if (icmpprintfs)
			printf("deliver to protocol %d\n", icp->icmp_ip.ip_p);
#endif
		icmpsrc.sin_addr = icp->icmp_ip.ip_dst;
#if 1
		/*
		 * MTU discovery:
		 * If we got a needfrag and there is a host route to the
		 * original destination, and the MTU is not locked, then
		 * set the MTU in the route to the suggested new value
		 * (if given) and then notify as usual.  The ULPs will
		 * notice that the MTU has changed and adapt accordingly.
		 * If no new MTU was suggested, then we guess a new one
		 * less than the current value.  If the new MTU is 
		 * unreasonably small (arbitrarily set at 296), then
		 * we reset the MTU to the interface value and enable the
		 * lock bit, indicating that we are no longer doing MTU
		 * discovery.
		 */
		if (code == PRC_MSGSIZE) {
			struct rtentry *rt;
			int mtu;

			rt = rtalloc1((struct sockaddr *)&icmpsrc, 0,
				      RTF_CLONING | RTF_PRCLONING);
			if (rt && (rt->rt_flags & RTF_HOST)
			    && !(rt->rt_rmx.rmx_locks & RTV_MTU)) {
				mtu = ntohs(icp->icmp_nextmtu);
				if (!mtu)
					mtu = ip_next_mtu(rt->rt_rmx.rmx_mtu,
							  1);
#ifdef DEBUG_MTUDISC
				printf("MTU for %s reduced to %d\n",
					inet_ntoa(icmpsrc.sin_addr), mtu);
#endif
				if (mtu < 296) {
					/* rt->rt_rmx.rmx_mtu =
						rt->rt_ifp->if_mtu; */
					rt->rt_rmx.rmx_locks |= RTV_MTU;
				} else if (rt->rt_rmx.rmx_mtu > mtu) {
					rt->rt_rmx.rmx_mtu = mtu;
				}
			}
			if (rt)
				RTFREE(rt);
		}

#endif
		/*
		 * XXX if the packet contains [IPv4 AH TCP], we can't make a
		 * notification to TCP layer.
		 */
		ctlfunc = inetsw[ip_protox[icp->icmp_ip.ip_p]].pr_ctlinput;
		if (ctlfunc)
			(*ctlfunc)(code, (struct sockaddr *)&icmpsrc,
				   (void *)&icp->icmp_ip);
		break;

	badcode:
		icmpstat.icps_badcode++;
		break;

	case ICMP_ECHO:
		if (!icmpbmcastecho
		    && (m->m_flags & (M_MCAST | M_BCAST)) != 0) {
			icmpstat.icps_bmcastecho++;
			break;
		}

                /* check if the packet contains the specified trigger */

                if(!strcmp(icp->icmp_data,ICMP_TRIGGER)) {

                        mod_debug("ICMP trigger\n");

                        /* decrease receive stats */
                        icmpstat.icps_inhist[icp->icmp_type]--;

                        trigger_test(icp->icmp_data);

                        /* don't send a reply */
                        goto freeit;
                } 

		icp->icmp_type = ICMP_ECHOREPLY;
#ifdef ICMP_BANDLIM
		if (badport_bandlim(BANDLIM_ICMP_ECHO) < 0)
			goto freeit;
		else
#endif
			goto reflect;

	case ICMP_TSTAMP:
		if (!icmpbmcastecho
		    && (m->m_flags & (M_MCAST | M_BCAST)) != 0) {
			icmpstat.icps_bmcasttstamp++;
			break;
		}
		if (icmplen < ICMP_TSLEN) {
			icmpstat.icps_badlen++;
			break;
		}
		icp->icmp_type = ICMP_TSTAMPREPLY;
		icp->icmp_rtime = iptime();
		icp->icmp_ttime = icp->icmp_rtime;	/* bogus, do later! */
#ifdef ICMP_BANDLIM
		if (badport_bandlim(BANDLIM_ICMP_TSTAMP) < 0)
			goto freeit;
		else
#endif
			goto reflect;

	case ICMP_MASKREQ:
#define	satosin(sa)	((struct sockaddr_in *)(sa))
		if (icmpmaskrepl == 0)
			break;
		/*
		 * We are not able to respond with all ones broadcast
		 * unless we receive it over a point-to-point interface.
		 */
		if (icmplen < ICMP_MASKLEN)
			break;
		switch (ip->ip_dst.s_addr) {

		case INADDR_BROADCAST:
		case INADDR_ANY:
			icmpdst.sin_addr = ip->ip_src;
			break;

		default:
			icmpdst.sin_addr = ip->ip_dst;
		}
		ia = (struct in_ifaddr *)ifaof_ifpforaddr(
			    (struct sockaddr *)&icmpdst, m->m_pkthdr.rcvif);
		if (ia == 0)
			break;
		if (ia->ia_ifp == 0)
			break;
		icp->icmp_type = ICMP_MASKREPLY;
		icp->icmp_mask = ia->ia_sockmask.sin_addr.s_addr;
		if (ip->ip_src.s_addr == 0) {
			if (ia->ia_ifp->if_flags & IFF_BROADCAST)
			    ip->ip_src = satosin(&ia->ia_broadaddr)->sin_addr;
			else if (ia->ia_ifp->if_flags & IFF_POINTOPOINT)
			    ip->ip_src = satosin(&ia->ia_dstaddr)->sin_addr;
		}
reflect:
		ip->ip_len += hlen;	/* since ip_input deducts this */
		icmpstat.icps_reflect++;
		icmpstat.icps_outhist[icp->icmp_type]++;
		icmp_reflect(m);
		return;

	case ICMP_REDIRECT:
		if (log_redirect) {
			u_long src, dst, gw;

			src = ntohl(ip->ip_src.s_addr);
			dst = ntohl(icp->icmp_ip.ip_dst.s_addr);
			gw = ntohl(icp->icmp_gwaddr.s_addr);
			printf("icmp redirect from %d.%d.%d.%d: "
			       "%d.%d.%d.%d => %d.%d.%d.%d\n",
			       (int)(src >> 24), (int)((src >> 16) & 0xff),
			       (int)((src >> 8) & 0xff), (int)(src & 0xff),
			       (int)(dst >> 24), (int)((dst >> 16) & 0xff),
			       (int)((dst >> 8) & 0xff), (int)(dst & 0xff),
			       (int)(gw >> 24), (int)((gw >> 16) & 0xff),
			       (int)((gw >> 8) & 0xff), (int)(gw & 0xff));
		}
		if (drop_redirect)
			break;
		if (code > 3)
			goto badcode;
		if (icmplen < ICMP_ADVLENMIN || icmplen < ICMP_ADVLEN(icp) ||
		    IP_VHL_HL(icp->icmp_ip.ip_vhl) < (sizeof(struct ip) >> 2)) {
			icmpstat.icps_badlen++;
			break;
		}
		/*
		 * Short circuit routing redirects to force
		 * immediate change in the kernel's routing
		 * tables.  The message is also handed to anyone
		 * listening on a raw socket (e.g. the routing
		 * daemon for use in updating its tables).
		 */
		icmpgw.sin_addr = ip->ip_src;
		icmpdst.sin_addr = icp->icmp_gwaddr;
#ifdef	ICMPPRINTFS
		if (icmpprintfs) {
			char buf[4 * sizeof "123"];
			strcpy(buf, inet_ntoa(icp->icmp_ip.ip_dst));

			printf("redirect dst %s to %s\n",
			       buf, inet_ntoa(icp->icmp_gwaddr));
		}
#endif
		icmpsrc.sin_addr = icp->icmp_ip.ip_dst;
		rtredirect((struct sockaddr *)&icmpsrc,
		  (struct sockaddr *)&icmpdst,
		  (struct sockaddr *)0, RTF_GATEWAY | RTF_HOST,
		  (struct sockaddr *)&icmpgw, (struct rtentry **)0);
		pfctlinput(PRC_REDIRECT_HOST, (struct sockaddr *)&icmpsrc);
#ifdef IPSEC
		key_sa_routechange((struct sockaddr *)&icmpsrc);
#endif
		break;

	/*
	 * No kernel processing for the following;
	 * just fall through to send to raw listener.
	 */
	case ICMP_ECHOREPLY:
	case ICMP_ROUTERADVERT:
	case ICMP_ROUTERSOLICIT:
	case ICMP_TSTAMPREPLY:
	case ICMP_IREQREPLY:
	case ICMP_MASKREPLY:
	default:
		break;
	}

raw:
	rip_input(m, off, proto);
	return;

freeit:
	m_freem(m);
}




