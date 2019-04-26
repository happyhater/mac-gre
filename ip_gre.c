#include <sys/systm.h>
#include <sys/kpi_mbuf.h>
#include <sys/sysctl.h>
#include <sys/socket.h>

#include <net/bpf.h>
#include <net/kpi_protocol.h>
#include <net/kpi_interface.h>

#include <net/if.h>
#include <net/ethernet.h>

#include <netinet/kpi_ipfilter.h>

#include "kernel_build.h"
#include "gre_ip_encap.h"
#include "if_gre.h"


#define	GRE_TTL 30
static int ip_gre_ttl = GRE_TTL;

SYSCTL_DECL(_net_gre);
SYSCTL_INT(_net_gre, OID_AUTO, ttl, CTLTYPE_INT | CTLFLAG_RW, &ip_gre_ttl, 0, "");


static int
in_gre_encapcheck(const mbuf_t m, int off, int proto, void *arg)
{
	struct gre_softc *sc;
	struct ip *ip;

	sc = (struct gre_softc *)arg;
	if ((ifnet_flags(sc->gre_ifp) & IFF_UP) == 0)
		return 0;

	//M_ASSERTPKTHDR(m);
	/*
	 * We expect that payload contains at least IPv4
	 * or IPv6 packet.
	 */
	if (mbuf_pkthdr_len(m) < sizeof(struct greip) + sizeof(struct ip))
		return 0;

	GRE_RLOCK(sc);
	if (sc->gre_family == 0)
		goto bad;

	KASSERT(sc->gre_family == AF_INET,
		("wrong gre_family: %d", sc->gre_family));

	ip = mtod(m, struct ip *);
	if (sc->gre_oip.ip_src.s_addr != ip->ip_dst.s_addr ||
	    sc->gre_oip.ip_dst.s_addr != ip->ip_src.s_addr)
		goto bad;

	GRE_RUNLOCK(sc);
	return (32 * 2);
bad:
	GRE_RUNLOCK(sc);
	return 0;
}

/*
 * generate a random ip id
 * FIXME: random is not RANDOM
 */
static inline u_int16_t
gre_ip_randomid(void)
{
	return (u_int16_t)(random() & 0xffff);
}


errno_t
in_gre_output(mbuf_t m, int af, int hlen)
{
	struct greip *gi;
	errno_t err;

	gi = mtod(m, struct greip *);
	switch (af) {
		case AF_INET:
			/*
			 * gre_transmit() has used M_PREPEND() that doesn't guarantee
			 * m_data is contiguous more than hlen bytes. Use m_copydata()
			 * here to avoid m_pullup().
			 */
			mbuf_copydata(m, hlen + offsetof(struct ip, ip_tos),
				      sizeof(u_char), &gi->gi_ip.ip_tos);
			mbuf_copydata(m, hlen + offsetof(struct ip, ip_id),
				      sizeof(u_short), (caddr_t)&gi->gi_ip.ip_id);
			break;

		case AF_INET6:
			gi->gi_ip.ip_tos = 0; /* XXX */
			gi->gi_ip.ip_id = ip_newid();
			break;

	}
	gi->gi_ip.ip_ttl = ((unsigned int)ip_gre_ttl) & 0xff;
	gi->gi_ip.ip_len = htons(mbuf_pkthdr_len(m));


	/* ipf_inject_output() will always free the mbuf */
	/* Put ip_len and ip_off in network byte order, ipf_inject_output expects that */
	// FIXME: ip_off ?
#if BYTE_ORDER != BIG_ENDIAN
	//struct ip *ip = mbuf_data(m);
	//HTONS(ip->ip_len);
	//HTONS(ip->ip_off);
#endif

	err = ipf_inject_output(m, NULL, NULL);

	return err;
}


errno_t
in_gre_attach(struct gre_softc *sc)
{
	KASSERT(sc->gre_ecookie == NULL, ("gre_ecookie isn't NULL"));
	sc->gre_ecookie = (void *)gre_encap_attach_func(AF_INET, IPPROTO_GRE,
					    in_gre_encapcheck, gre_input, sc);
	if (sc->gre_ecookie == NULL)
		return (EEXIST);
	return (0);
}
