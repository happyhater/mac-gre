#ifndef _NET_IF_GRE_H
#define _NET_IF_GRE_H

#include <libkern/OSTypes.h>
#include <sys/types.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

#include "gre_ip_encap.h"


/* GRE header according to RFC 2784 and RFC 2890 */
struct grehdr {
	uint16_t	gre_flags;	/* GRE flags */
#define	GRE_FLAGS_CP	0x8000		/* checksum present */
#define	GRE_FLAGS_KP	0x2000		/* key present */
#define	GRE_FLAGS_SP	0x1000		/* sequence present */
#define	GRE_FLAGS_MASK	(GRE_FLAGS_CP|GRE_FLAGS_KP|GRE_FLAGS_SP)
	uint16_t	gre_proto;	/* protocol type */
	uint32_t	gre_opts[0];	/* optional fields */
} __attribute__((__packed__));

struct greip {
	struct ip	gi_ip;
	struct grehdr	gi_gre;
} __attribute__((__packed__));

struct greip6 {
	struct ip6_hdr	gi6_ip6;
	struct grehdr	gi6_gre;
} __attribute__((__packed__));


struct gre_softc {
	ifnet_t			gre_ifp;
	LIST_ENTRY(gre_softc)	gre_list;
	lck_rw_t		*gre_lock;
	int			gre_family;	/* AF of delivery header */
	uint32_t		gre_iseq;
	uint32_t		gre_oseq;
	uint32_t		gre_key;
	uint32_t		gre_options;
	uint32_t		gre_mtu;
	u_int			gre_hlen;	/* header size */
	union {
		void		*hdr;
		struct greip	*gihdr;
		struct greip6	*gi6hdr;
	} gre_uhdr;
	const struct gre_encaptab *gre_ecookie;

	// for darwin
	lck_mtx_t		*detach_mtx;	/* interface state mutex */
	u_int			is_detaching;	/* state of the interface */
	volatile SInt32		sc_refcnt;	/* reference count */
};

//#define	GRE2IFP(sc)		((sc)->gre_ifp)
#define	GRE_RLOCK(sc)		lck_rw_lock_shared((sc)->gre_lock)
#define	GRE_RUNLOCK(sc)		lck_rw_unlock_shared((sc)->gre_lock)
#define	GRE_WLOCK(sc)		lck_rw_lock_exclusive((sc)->gre_lock)
#define	GRE_WUNLOCK(sc)		lck_rw_unlock_exclusive((sc)->gre_lock)

#define sx_xlock(lck)		lck_rw_lock_exclusive(lck)
#define sx_xunlock(lck)		lck_rw_unlock_exclusive(lck)
#define sx_assert(lck, st)

#define	gre_hdr			gre_uhdr.hdr
#define	gre_gihdr		gre_uhdr.gihdr
#define	gre_gi6hdr		gre_uhdr.gi6hdr
#define	gre_oip			gre_gihdr->gi_ip
#define	gre_oip6		gre_gi6hdr->gi6_ip6


/*
 * CISCO uses special type for GRE tunnel created as part of WCCP
 * connection, while in fact those packets are just IPv4 encapsulated
 * into GRE.
 */
#define ETHERTYPE_WCCP		0x883E


#define GRESADDRS	_IOW('i', 101, struct ifreq)
#define GRESADDRD	_IOW('i', 102, struct ifreq)
#define GREGADDRS	_IOWR('i', 103, struct ifreq)
#define GREGADDRD	_IOWR('i', 104, struct ifreq)
#define GRESPROTO	_IOW('i' , 105, struct ifreq)
#define GREGPROTO	_IOWR('i', 106, struct ifreq)

#define	GREGKEY		_IOWR('i', 107, struct ifreq)
#define	GRESKEY		_IOW('i', 108, struct ifreq)
#define	GREGOPTS	_IOWR('i', 109, struct ifreq)
#define	GRESOPTS	_IOW('i', 110, struct ifreq)

#define	GRE_ENABLE_CSUM		0x0001
#define	GRE_ENABLE_SEQ		0x0002
#define	GRE_OPTMASK		(GRE_ENABLE_CSUM|GRE_ENABLE_SEQ)


extern void	gre_sc_reference(struct gre_softc *);
extern SInt32	gre_sc_release(struct gre_softc *);

extern int	gre_proto_register(void);
extern void	gre_proto_unregister(void);

extern int	gre_if_init(void);
extern int	gre_if_dispose(void);
extern int	gre_if_attach(void);

extern void	gre_input(mbuf_t *, int *, int, void *);

extern errno_t	in_gre_output(mbuf_t, int, int);
extern errno_t	in_gre_attach(struct gre_softc *);
extern errno_t	in6_gre_output(mbuf_t, int, int);
extern errno_t	in6_gre_attach(struct gre_softc *);

#endif
