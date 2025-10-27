# BPF driver

We know we can send layer 2 packest using the BPF driver. We thus use this driver as a basis for the implementation of sending an arbitrary packet over the network from within the kernel. All memory for this part of the implementation is defined inside the kernel.

We have the sequence when initialising the BPF interface, so we can understand how the BPF driver sets up and uses the network interface.

```c
  ifreq ifr{};
  strlcpy(&ifr.ifr_name[0], bpf_intf.c_str(), IFNAMSIZ);
  ioctl(fd, BIOCSETIF, &ifr);
  
  unsigned int hdr_complete = 1;
  ioctl(fd, BIOCSHDRCMPLT, &hdr_complete);
```

In the FreeBSD kernel, we see the function `bpfattach` which appears to be called by the `iflib` interface, and some network drivers. On analysing this function, if it is never called, then BPF will never send traffic on the interface (because it doesn't exist in the `bpf_iflist`).

```c
void
bpfattach(struct ifnet *ifp, u_int dlt, u_int hdrlen)
{
	bpfattach2(ifp, dlt, hdrlen, &ifp->if_bpf);
}

/*
 * Attach an interface to bpf.  ifp is a pointer to the structure
 * defining the interface to be attached, dlt is the link layer type,
 * and hdrlen is the fixed size of the link header (variable length
 * headers are not yet supporrted).
 */
void
bpfattach2(struct ifnet *ifp, u_int dlt, u_int hdrlen,
    struct bpf_if **driverp)
{
	struct bpf_if *bp;

	KASSERT(*driverp == NULL,
	    ("bpfattach2: driverp already initialized"));

	bp = malloc(sizeof(*bp), M_BPF, M_WAITOK | M_ZERO);

	CK_LIST_INIT(&bp->bif_dlist);
	CK_LIST_INIT(&bp->bif_wlist);
	bp->bif_ifp = ifp;
	bp->bif_dlt = dlt;
	bp->bif_hdrlen = hdrlen;
	bp->bif_bpf = driverp;
	bp->bif_refcnt = 1;
	*driverp = bp;
	/*
	 * Reference ifnet pointer, so it won't freed until
	 * we release it.
	 */
	if_ref(ifp);
	BPF_LOCK();
	CK_LIST_INSERT_HEAD(&bpf_iflist, bp, bif_next);
	BPF_UNLOCK();

	if (bootverbose && IS_DEFAULT_VNET(curvnet))
		if_printf(ifp, "bpf attached\n");
}
```

So we can see that when BPF has it registered, it adds a reference to the ifnet structure with a call to `if_ref(ifp)`.

The free has to be done carefully. BSD uses `NET_EPOCH_CALL(bpfif_free, &bp->epoch_ctx)` to make sure that this is done in a safe way. Our own driver would have to be careful of freeing memory if operations can occur in parallel (and we assume that everything is multithreaded in the kernel).

So going back on how we initialise the BPF program using the `ioctl` calls:

```c  
static	int
bpfioctl(struct cdev *dev, u_long cmd, caddr_t addr, int flags,
    struct thread *td)
{
	struct bpf_d *d;
	int error;

	error = devfs_get_cdevpriv((void **)&d);

	case BIOCSETIF:
			error = bpf_setif(d, (struct ifreq *)addr);

	case BIOCSHDRCMPLT:
		BPFD_LOCK(d);
		d->bd_hdrcmplt = *(u_int *)addr ? 1 : 0;
		BPFD_UNLOCK(d);
		break;
}
```

So we know that `d->bd_hdrcmplt == 1`. Looking at how the interface is set:

```c
/*
 * Detach a file from its current interface (if attached at all) and attach
 * to the interface indicated by the name stored in ifr.
 * Return an errno or 0.
 */
static int
bpf_setif(struct bpf_d *d, struct ifreq *ifr)
{
	struct bpf_if *bp;
	struct ifnet *theywant;

	BPF_LOCK_ASSERT();

	theywant = ifunit(ifr->ifr_name);
	if (theywant == NULL)
		return (ENXIO);
	/*
	 * Look through attached interfaces for the named one.
	 */
	CK_LIST_FOREACH(bp, &bpf_iflist, bif_next) {
		if (bp->bif_ifp == theywant &&
		    bp->bif_bpf == &theywant->if_bpf)
			break;
	}
	if (bp == NULL)
		return (ENXIO);

	MPASS(bp == theywant->if_bpf);
	/*
	 * At this point, we expect the buffer is already allocated.  If not,
	 * return an error.
	 */
	switch (d->bd_bufmode) {
	case BPF_BUFMODE_BUFFER:
	case BPF_BUFMODE_ZBUF:
		if (d->bd_sbuf == NULL)
			return (EINVAL);
		break;

	default:
		panic("bpf_setif: bufmode %d", d->bd_bufmode);
	}
	if (bp != d->bd_bif)
		bpf_attachd(d, bp);
	else {
		BPFD_LOCK(d);
		reset_d(d);
		BPFD_UNLOCK(d);
	}
	return (0);
}
```

Not much here except for the `ifunit` call. Here is how we know that each driver must have called `bpfattach()` prior, else the `ioctl` would have returned `ENXIO`, which it obviously doesn't (because the code works). We're using `BPF_BUFMODE_BUFFER` by default, but this doesn't affect the write operations, only a copy/zero-copy read operation on BPF data. The rest of the code is interesting for the BPF driver, but less so for us just sending out raw data.

Finally the write operation

```c
static int
bpfwrite(struct cdev *dev, struct uio *uio, int ioflag)
{
	struct epoch_tracker et;
	struct mbuf *m, *mc;
	struct sockaddr dst;
	int error, hlen;
	struct bpf_d *d;

	error = devfs_get_cdevpriv((void **)&d);

	NET_EPOCH_ENTER(et);

	ifp = bp->bif_ifp;
	if ((ifp->if_flags & IFF_UP) == 0) {
		error = ENETDOWN;
		goto out_locked;
	}
	
	NET_EPOCH_EXIT(et);

	error = bpf_movein(uio, (int)bp->bif_dlt, ifp,
	    &m, &dst, &hlen, d);

	if (d->bd_hdrcmplt)
		dst.sa_family = pseudo_AF_HDRCMPLT;

	m->m_pkthdr.len -= hlen;
	m->m_len -= hlen;
	m->m_data += hlen;	/* XXX */

	bzero(&ro, sizeof(ro));
	if (hlen != 0) {
		ro.ro_prepend = (u_char *)&dst.sa_data;
		ro.ro_plen = hlen;
		ro.ro_flags = RT_HAS_HEADER;
	}

	NET_EPOCH_ENTER(et);
	error = (*ifp->if_output)(ifp, m, &dst, &ro);
	NET_EPOCH_EXIT(et);
	return error;
}
```

Because `d->bd_hdrcmplt` is non-zero, we always know the `dst.sa_family = pseudo_AF_HDRCMPLT`.

The structure that allocates the `mbuf m`, defines `sockaddr dst` and gets the header length `hlen` is done by `bpf_movein`:

```c
static int
bpf_movein(struct uio *uio, int linktype, struct ifnet *ifp, struct mbuf **mp,
    struct sockaddr *sockp /*(dst)*/, int *hdrlen, struct bpf_d *d)
{
	switch (linktype) {
	case DLT_EN10MB:
		sockp->sa_family = AF_UNSPEC;
		/* XXX Would MAXLINKHDR be better? */
		hlen = ETHER_HDR_LEN;
		break;
	}

	len = uio->uio_resid;
	if (len < hlen || len - hlen > ifp->if_mtu)
		return (EMSGSIZE);
```

The link type (determined by adding a debug message on the value of `linktype` and rebuilding, running the kernel), is `DLT_EN10MB` which has the value of 1. The value of `ETHER_HDR_LEN` is 14 bytes (6 bytes destination MAC, 6 bytes source MAC, 2 bytes protocol, e.g. internet IPv4 0f 0x0800).

Following is allocation of the `mbuf` data for the network packet:

```c
	/*
	 * Allocate a mbuf for our write, since m_get2 fails if len >= to
	 * MJUMPAGESIZE, use m_getjcl for bigger buffers
	 */
	if (len < MJUMPAGESIZE)
		m = m_get2(len, M_WAITOK, MT_DATA, M_PKTHDR);
	else if (len <= MJUM9BYTES)
		m = m_getjcl(M_WAITOK, MT_DATA, M_PKTHDR, MJUM9BYTES);
	else if (len <= MJUM16BYTES)
		m = m_getjcl(M_WAITOK, MT_DATA, M_PKTHDR, MJUM16BYTES);
	else
		m = NULL;
	if (m == NULL)
		return (EIO);
	m->m_pkthdr.len = m->m_len = len;
```

It has changed slightly in FreeBSD 15:

```c
	/* Allocate a mbuf, up to MJUM16BYTES bytes, for our write. */
	m = m_get3(len, M_WAITOK, MT_DATA, M_PKTHDR);
	if (m == NULL)
		return (EIO);
	m->m_pkthdr.len = m->m_len = len;
```

The `MJUMPPAGESIZE` is a page size, 4096 bytes (or on ARM that has 16kB, would be 8192 bytes). It's defined in `sys/params.h` as:

```c
/*
 * Constants related to network buffer management.
 * MCLBYTES must be no larger than PAGE_SIZE.
 */
#ifndef	MSIZE
#define	MSIZE		256		/* size of an mbuf */
#endif

#ifndef	MCLSHIFT
#define MCLSHIFT	11		/* convert bytes to mbuf clusters */
#endif	/* MCLSHIFT */

#define MCLBYTES	(1 << MCLSHIFT)	/* size of an mbuf cluster */

#if PAGE_SIZE < 2048
#define	MJUMPAGESIZE	MCLBYTES
#elif PAGE_SIZE <= 8192
#define	MJUMPAGESIZE	PAGE_SIZE
#else
#define	MJUMPAGESIZE	(8 * 1024)
#endif

#define	MJUM9BYTES	(9 * 1024)	/* jumbo cluster 9k */
#define	MJUM16BYTES	(16 * 1024)	/* jumbo cluster 16k */
```

the page sizse is defined in `arm64/include/param.h`:

```c
/*
 * CACHE_LINE_SIZE is the compile-time maximum cache line size for an
 * architecture.  It should be used with appropriate caution.
 */
#define	CACHE_LINE_SHIFT	7
#define	CACHE_LINE_SIZE		(1 << CACHE_LINE_SHIFT)

#define	PAGE_SHIFT_4K	12
#define	PAGE_SIZE_4K	(1 << PAGE_SHIFT_4K)
#define	PAGE_MASK_4K	(PAGE_SIZE_4K - 1)

#define	PAGE_SHIFT_16K	14
#define	PAGE_SIZE_16K	(1 << PAGE_SHIFT_16K)
#define	PAGE_MASK_16K	(PAGE_SIZE_16K - 1)

#define	PAGE_SHIFT_64K	16
#define	PAGE_SIZE_64K	(1 << PAGE_SHIFT_64K)
#define	PAGE_MASK_64K	(PAGE_SIZE_64K - 1)

#define	PAGE_SHIFT	PAGE_SHIFT_4K
#define	PAGE_SIZE	PAGE_SIZE_4K
#define	PAGE_MASK	PAGE_MASK_4K
```

This makes `MJUMPAGESIZE` the value 0f 4096. So if we allocate a "normal" Ethernet packet, this uses the `m_get2` function.

The `m_get2(len, M_WAITOK, MT_DATA, M_PKTHDR)` function allocates all necessary memory for the Ethernet packet. The resulting `mbuf` can hold up to `len` bytes of data. The `mbuf` returned has a `struct pkthdr m_pkthdr` defined, i.e. the start of a record. 

The `m_get2` function is defined in `kern_mbuf.c`. Because the memory request is less than 2kB, memory is allocated by calling `uma_zalloc_arg(zone_pack, &args, how)`. The `zone_pack` initialises with `mb_zinit_pack()` function on the first alloc.

The `mb_zinit_pack()` function does the work of calling `uma_zalloc_arg(zone_clust, m, how)`, so now it allocates a 2kB memory region. The `zone_clust` ctor is given an `mbuf` in the arg, and the `mb_ctor_clust()` function sets this up as the `m->m_ext.ext_buf`. So now there are actually two `mbuf` objects allocated, the header from `zone_mbuf` (this is the parent of `zone_pack`), the external data is from `zone_cluster`.

When the `mbuf` from `zone_mbuf` and `zone_packed` is created first, the ctor is called:

```c
/*
 * Initialize an mbuf with linear storage.
 *
 * Inline because the consumer text overhead will be roughly the same to
 * initialize or call a function with this many parameters and M_PKTHDR
 * should go away with constant propagation for !MGETHDR.
 */
static __inline int
m_init(struct mbuf *m, int how, short type, int flags)
{
	int error;

	m->m_next = NULL;
	m->m_nextpkt = NULL;
	m->m_data = m->m_dat;
	m->m_len = 0;
	m->m_flags = flags;
	m->m_type = type;
	if (flags & M_PKTHDR)
		error = m_pkthdr_init(m, how);
	else
		error = 0;

	MBUF_PROBE5(m__init, m, how, type, flags, error);
	return (error);
}
```

and because `M_PKTHDR` is used here:

```c
/*
 * Non-inlined part of m_init().
 */
int
m_pkthdr_init(struct mbuf *m, int how)
{
	m->m_data = m->m_pktdat;
	bzero(&m->m_pkthdr, sizeof(m->m_pkthdr));
	return (0);
}
```

The `struct pkthdr m_pkthdr` contains the packet length, flowid, checksum and offload features, the fibnum.

When the `zone_cluster` allocates an external mbuf, and adds it to the `mbuf` from `zone_pack`, it overwrites the `m->m_data` to the new cluster:

```c
m->m_data = m->m_ext.ext_buf;
```

When the memory block from `zone_pack` is freed, it first frees the memory in the `m->m_ext.ext_buf` back to the `zone_cluster`. So the `zone_cluster` is always used to allocate extra memory on the `ext_buf` element.

```c
error = uiomove(mtod(m, u_char *), len, uio);
```

This copies the data from the userspace `write()` call, up to `len` bytes of length, into the just allocated `mbuf->m_data`. The `mtod` function is simple:

```c
#define	mtod(m, t)	((t)((m)->m_data))
```

so it just type casts the packet data. From what we've seen above, it returns the 2kB buffer data from the `zone_cluster`.

So now the input data is copied into the data of `m->m_data`. This includes the Ethernet header.

Finally, multicast settings are set in the `bpf_movein()` function:

```c
	/* Check for multicast destination */
	switch (linktype) {
	case DLT_EN10MB:
		eh = mtod(m, struct ether_header *);
		if (ETHER_IS_MULTICAST(eh->ether_dhost)) {
			if (bcmp(ifp->if_broadcastaddr, eh->ether_dhost,
			    ETHER_ADDR_LEN) == 0)
				m->m_flags |= M_BCAST;
			else
				m->m_flags |= M_MCAST;
		}
		if (d->bd_hdrcmplt == 0) {
			memcpy(eh->ether_shost, IF_LLADDR(ifp),
			    sizeof(eh->ether_shost));
		}
		break;
	}
```

And because `bd_hdrcmplt` is non-zero, we use the Ethernet header in the original packet as the source. The source packet is always the first 6-bytes, so the `mtod` is just typecasting the beginning of the packet to the Ethernet header.

Finally, the last part of the socket is defined:

```c
	/*
	 * Make room for link header, and copy it to sockaddr
	 */
	if (hlen != 0) {
		bcopy(mtod(m, const void *), sockp->sa_data, hlen);
	}
	*hdrlen = hlen;
```

So it copies the header, of 6 bytes, from `m->m_data` to `sockp->sa_data`. which is the destination MAC address.

Continuing with the write of `bpfwrite()`:

```c
	m->m_pkthdr.len -= hlen;
	m->m_len -= hlen;
	m->m_data += hlen;	/* XXX */

	bzero(&ro, sizeof(ro));
	if (hlen != 0) {
		ro.ro_prepend = (u_char *)&dst.sa_data;
		ro.ro_plen = hlen;
		ro.ro_flags = RT_HAS_HEADER;
	}
```

The `bpf_movein` function has set the `m->m_pkthdr.len` and `m_len` to be the length of our L2 Ethernet packet. It removes the destination header, as that information is now in the socket. The routing information now contains the header information.

The `bpfwrite()` then:

```c
	if (d->bd_pcp != 0)
		vlan_set_pcp(m, d->bd_pcp);
```

The function `vlan_set_pcp` is defined in `if_vlan_var.h`:

```c
static inline int
vlan_set_pcp(struct mbuf *m, uint8_t prio)
{
	struct m_tag *mtag;

	KASSERT(prio <= VLAN_PCP_MAX,
	    ("%s with invalid pcp", __func__));

	mtag = m_tag_locate(m, MTAG_8021Q, MTAG_8021Q_PCP_OUT, NULL);
	if (mtag == NULL) {
		mtag = m_tag_alloc(MTAG_8021Q, MTAG_8021Q_PCP_OUT,
		    sizeof(uint8_t), M_NOWAIT);
		if (mtag == NULL)
			return (ENOMEM);
		m_tag_prepend(m, mtag);
	}

	*(uint8_t *)(mtag + 1) = prio;

	return (0);
}
```

So it looks for the tag `MTAG_8021Q` (note a tag is not the 2-byte Ethernet protocol 0x8100) in the interface structure (see `uipc_mbuf2.c` for the implementation of `m_tag_locate`). The tag doesn't exist in the code that is just analysed. So a new tag will be allocated.

The network driver is now requested to transmit the packet:

```c
error = (*ifp->if_output)(ifp, m, &dst, &ro);
```

The next step is now to implement and update these notes.

