/*
 * Copyright (C) 2012, Ming Chen
 * 
 * A target to save energy by directing reads/writes to different physical
 * disks based on energy characteristics. 
 *
 * This file is released under the GPL.
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/blkdev.h>
#include <linux/bio.h>
#include <linux/log2.h>
#include <linux/dm-io.h>
#include <linux/dm-kcopyd.h>
#include <linux/vmalloc.h>
#include <linux/jiffies.h>
#include <linux/bitmap.h>
#include <linux/list.h>
#include <linux/spinlock.h>

#include <linux/device-mapper.h>

#define DM_MSG_PREFIX "energy"

/*
 * Magic for persistent energy header: "EnEg"
 */
#define ENERGY_MAGIC 0x45614567
#define ENERGY_VERSION 7
#define ENERGY_DAEMON "kenergyd"

/* The first disk is prime disk. */
#define PRIME_DISK 0

#define SECTOR_SIZE (1 << SECTOR_SHIFT)

#define count_sector(x) (((x) + SECTOR_SIZE - 1) >> SECTOR_SHIFT)

/* Return metadata's size in sector. */
#define header_size() \
    count_sector(sizeof(struct energy_header_disk))

#define table_size(ec) \
    count_sector(ec->header.capacity * sizeof(struct vextent_disk))

/* Return size of bitmap array */
#define bitmap_size(len) dm_round_up(len, sizeof(unsigned long))

#define extent_size(ec) (ec->header.ext_size)
#define vdisk_size(ec) (ec->header.capacity)
#define prime_size(ec) (ec->disks[PRIME_DISK].capacity)
#define fdisk_nr(ec) (ec->header.ndisk)

/* 
 * When requesting a new bio, the number of requested bvecs has to be
 * less than BIO_MAX_PAGES. Otherwise, null is returned. In dm-io.c,
 * this return value is not checked and kernel Oops may happen. We set
 * the limit here to avoid such situations. (2 additional bvecs are
 * required by dm-io for bookeeping.) (From dm-cache)
 */
#define MAX_SECTORS ((BIO_MAX_PAGES - 2) * (PAGE_SIZE >> SECTOR_SHIFT))

/* Size of reserved free extent on prime disk */
#define EXTENT_FREE 2      
#define EXTENT_LOW 1

#define array_too_big(fixed, obj, num) \
	((num) > (UINT_MAX - (fixed)) / (obj))

typedef uint64_t extent_t;

/*
 * Header in memory, contained in energy context (energy_c).
 */
struct energy_header {
    uint32_t magic;
    uint32_t version;
    uint32_t ndisk;
    uint32_t ext_size;
    extent_t capacity;          /* capacity in extent */
};

/*
 * Header on disk, followed by metadata of mapping table.
 */
struct energy_header_disk {
    __le32 magic;
    __le32 version;
    __le32 ndisk;
    __le32 ext_size;
    __le64 capacity;
} __packed;

/* Virtual extent states */
#define VES_PRESENT 0x01
#define VES_ACCESS  0x02
#define VES_MIGRATE 0x04

/*
 * Virtual extent in memory.
 */
struct vextent {
    extent_t eid;               /* physical extent id */
    uint32_t state;             
    uint32_t counter;           /* how many times are accessed */
    uint64_t tick;              /* timestamp of latest access */
};

/*
 * Extent metadata on disk.
 */
struct vextent_disk {
    __le64 eid;
    __le32 state;
    __le32 counter;
} __packed;

/*
 * Physical extent.
 */
struct extent {
    struct vextent *vext;       /* virtual extent */
    struct list_head list;
};

/*
 * Ring buffer of physical extent.
 */
struct extent_buffer {
    extent_t data[EXTENT_FREE]; /* array of physical extent id */
    unsigned capacity;          
    unsigned cursor;            /* cursor of first entent id */
    unsigned count;             /* number of valid extents */
};

struct mapped_disk {
    struct dm_dev *dev;
    extent_t capacity;          /* capacity in extent */
    extent_t free_nr;           /* number of free extents */
    extent_t offset;            /* offset within virtual disk in extent */
};

struct energy_c {
    struct dm_target *ti;

    struct energy_header header;
    uint32_t flags;
    uint32_t ext_shift;

    struct mapped_disk *disks;

    struct vextent *table;       /* mapping table */

    struct extent   *prime_extents; /* physical extents on prime disk */
    struct list_head prime_free;    /* free extents on prime disk */
    struct list_head prime_use;     /* in-use extents on prime disk */

    unsigned long *bitmap;      /* bitmap of extent, '0' for free extent */
    spinlock_t lock;            /* protect table, free and bitmap */

    struct dm_io_client *io_client;
    struct dm_kcopyd_client *kcp_client;

    struct work_struct eviction_work;   /* work of evicting prime extent */
    struct extent *eviction_cursor;
};

static struct workqueue_struct *kenergyd_wq;

static inline unsigned wrap(unsigned i, unsigned limit)
{
    return (i >= limit) ? i - limit : i;
}

static inline bool buffer_full(struct extent_buffer *buf)
{
    return buf->count == buf->capacity;
}

static inline bool buffer_empty(struct extent_buffer *buf)
{
    return buf->count == 0;
}

static inline extent_t consume_buffer(struct extent_buffer *buf)
{
    extent_t out = buf->data[buf->cursor];

    buf->cursor = wrap(buf->cursor + 1, buf->capacity);
    --(buf->count);

    return out;
}

static inline void produce_buffer(struct extent_buffer *buf, extent_t in)
{
    buf->data[wrap(buf->cursor + buf->count, buf->capacity)] = in;
    ++(buf->count);
}

static struct energy_c *alloc_context(struct dm_target *ti, 
        uint32_t ndisk, uint32_t ext_size)
{
    struct energy_c *ec;

    ec = kmalloc(sizeof(struct energy_c), GFP_KERNEL);
    if (!ec)
        return ec;

    ec->disks = kmalloc(sizeof(struct mapped_disk) * ndisk, GFP_KERNEL);
    if (!ec->disks) {
        kfree(ec);
        return NULL;
    }

    ec->ti = ti;
    ti->private = ec;

    ec->ext_shift = ffs(ext_size) - 1;
    ec->header.magic = ENERGY_MAGIC;
    ec->header.version = ENERGY_VERSION;
    ec->header.ndisk = ndisk;
    ec->header.ext_size = ext_size;
    ec->header.capacity = (ti->len >> ec->ext_shift);

    spin_lock_init(&ec->lock);

    ec->table = NULL;           /* table not allocated yet */
    ec->io_client = NULL;
    ec->kcp_client = NULL;
    ec->prime_extents = NULL;
    ec->eviction_cursor = NULL;

    return ec;
}

static void free_context(struct energy_c *ec)
{
    BUG_ON(!ec || !(ec->disks));

    if (ec->table) {
        vfree(ec->table);
        ec->table = NULL;
    }
    if (ec->bitmap) {
        vfree(ec->bitmap);
        ec->bitmap = NULL;
    }
    if (ec->prime_extents) {
        vfree(ec->prime_extents);
        ec->prime_extents = NULL;
    }

    kfree(ec->disks);
    kfree(ec);
}

static inline void header_to_disk(struct energy_header *core, 
        struct energy_header_disk *disk)
{   
    disk->magic = cpu_to_le32(core->magic);
    disk->version = cpu_to_le32(core->version);
    disk->ndisk = cpu_to_le32(core->ndisk);
    disk->ext_size = cpu_to_le32(core->ext_size);
    disk->capacity = cpu_to_le64(core->capacity);
}

static inline void header_from_disk(struct energy_header *core,
        struct energy_header_disk *disk)
{   
    core->magic = le32_to_cpu(disk->magic);
    core->version = le32_to_cpu(disk->version);
    core->ndisk = le32_to_cpu(disk->ndisk);
    core->ext_size = le32_to_cpu(disk->ext_size);
    core->capacity = le64_to_cpu(disk->capacity);
}

static inline void extent_to_disk(struct vextent *core, 
        struct vextent_disk *disk)
{
    disk->eid = cpu_to_le64(core->eid);
    disk->state = cpu_to_le32(core->state);
    disk->counter = cpu_to_le32(core->counter);
}

static inline void extent_from_disk(struct vextent *core,
        struct vextent_disk *disk)
{
    core->eid = le64_to_cpu(disk->eid);
    core->state = le32_to_cpu(disk->state);
    core->counter = le32_to_cpu(disk->counter);
}

/*
 * Get a mapped disk and check if it is sufficiently large.
 */
static int get_mdisk(struct dm_target *ti, struct energy_c *ec, 
        unsigned idisk, char **argv)
{
	sector_t dev_size;
    sector_t len;
    char *end;

    ec->disks[idisk].capacity = simple_strtoull(argv[1], &end, 10);
    if (*end)
        return -EINVAL;

    len = ec->disks[idisk].capacity << ec->ext_shift; 
#ifdef DME_OLD_KERNEL
    if (dm_get_device(ti, argv[0], dm_table_get_mode(ti->table), 0, 
                len, &ec->disks[idisk].dev))
#else
    if (dm_get_device(ti, argv[0], dm_table_get_mode(ti->table), 
                &ec->disks[idisk].dev))
#endif
        return -ENXIO;

    /* device capacity should be large enough for extents and metadata */
    dev_size = ec->disks[idisk].dev->bdev->bd_inode->i_size >> SECTOR_SHIFT;
    if (dev_size < len + header_size() + table_size(ec)) 
        return -ENOSPC;

    return 0;
}

/*
 * Put disk devices.
 */
static void put_disks(struct energy_c *ec, int ndisk)
{
    int i;

    for (i = 0; i < ndisk; ++i) {
        dm_put_device(ec->ti, ec->disks[i].dev);
    }
}

/*
 * Get all disk devices and check if disk size matches.
 */
static int get_disks(struct energy_c *ec, char **argv)
{
    int r;
    unsigned i;
    extent_t ext_count = 0;

    for (i = 0; i < fdisk_nr(ec); ++i, argv += 2) {
        r = get_mdisk(ec->ti, ec, i, argv);
        if (r < 0) {
            put_disks(ec, i);
            break;
        }
        ec->disks[i].offset = ext_count;
        ext_count += ec->disks[i].capacity;
    }

    /* Virtual disk size should match sum of physical disks' size */
    if (vdisk_size(ec) != ext_count) {
        DMERR("Disk length dismatch");
        r = -EINVAL;
    }

    return r;
}

/*
 * Check if physical extent 'ext' is on prime disk.
 */
static inline bool on_prime(struct energy_c *ec, extent_t eid)
{
    return eid < prime_size(ec);
}

static inline extent_t ext2id(struct energy_c *ec, struct extent *ext)
{
    return (ext - ec->prime_extents)/sizeof(struct extent);
}

/*
 * Return physical disk id and offset of physical extent.
 */
static inline void extent_on_disk(struct energy_c *ec, extent_t *eid,
        unsigned *i)
{
    BUG_ON(*eid >= vdisk_size(ec));
    *i = 0;
    while (*i < fdisk_nr(ec) && *eid >= ec->disks[*i].capacity) {
        *eid -= ec->disks[(*i)++].capacity;
    }
}

static inline struct extent *next_extent(struct extent *ext)
{
    return list_entry(ext->list.next, struct extent, list);
}

/*
 * Get a prime extent.
 */
static inline int get_prime(struct energy_c *ec, extent_t *eid)
{
    struct extent *first;

    if (list_empty(&ec->prime_free)) 
        return -ENOSPC;

    first = list_first_entry(&(ec->prime_free), struct extent, list);
    list_del(&first->list);
    list_add(&first->list, &ec->prime_use);
    *eid = ext2id(ec, first);

    ec->disks[PRIME_DISK].free_nr--;
    bitmap_set(ec->bitmap, *eid, 1);
    DMDEBUG("get_prime: %llu extents left", ec->disks[PRIME_DISK].free_nr);

    return 0;
}

/*
 * Put a prime extent.
 */
static inline void put_prime(struct energy_c *ec, extent_t eid)
{
    struct extent *ext;

    BUG_ON(eid >= prime_size(ec));
    ext = ec->prime_extents + eid;
    ext->vext = NULL;
    list_del(&ext->list);
    list_add(&ext->list, &(ec->prime_free));
    ec->disks[PRIME_DISK].free_nr++;
    bitmap_clear(ec->bitmap, eid, 1);
    DMDEBUG("put_prime: %llu extents left", ec->disks[PRIME_DISK].free_nr);
}

/*
 * Get a physical extent. 
 */
static int get_extent(struct energy_c *ec, extent_t *eid, bool prime)
{
    unsigned i;

    if (prime && get_prime(ec, eid) == 0) 
        return 0;

    for (i = PRIME_DISK+1; i < fdisk_nr(ec); ++i) {
        if (ec->disks[i].free_nr > 0) {
            *eid = find_next_zero_bit(ec->bitmap, vdisk_size(ec), 
                    ec->disks[i].offset);
            ec->disks[i].free_nr--;
            bitmap_set(ec->bitmap, *eid, 1);
            return 0;
        }
    }

    return -ENOSPC;
}

/*
 * Put a physcial extent.
 */
static void put_extent(struct energy_c *ec, extent_t eid)
{
    unsigned i;

    BUG_ON(eid >= vdisk_size(ec));
    for (i = 0; eid >= ec->disks[i].capacity + ec->disks[i].offset; ++i)
        ;

    if (i == PRIME_DISK) {   /* prime disk */
        put_prime(ec, eid);
    } else { 
        ec->disks[i].free_nr++;
        bitmap_clear(ec->bitmap, eid, 1);
    }
}

/*
 * Wrapper function for new dm_io API.
 */
static int dm_io_sync_vm(unsigned num_regions, struct dm_io_region *where,
        int rw, void *data, unsigned long *error_bits, struct energy_c *ec)
{
	struct dm_io_request iorq;

	iorq.bi_rw= rw;
	iorq.mem.type = DM_IO_VMA;
	iorq.mem.ptr.vma = data;
	iorq.notify.fn = NULL;
	iorq.client = ec->io_client;

	return dm_io(&iorq, num_regions, where, error_bits);
}

static inline void locate_header(struct dm_io_region *where, 
        struct energy_c *ec, unsigned idisk)
{
    where->bdev = ec->disks[idisk].dev->bdev;
    where->sector = ec->disks[idisk].capacity << ec->ext_shift;
    where->count = header_size();
    BUG_ON(where->count > MAX_SECTORS);
}

/*
 * Dump metadata header to a disk.
 */
static int dump_header(struct energy_c *ec, unsigned idisk)
{
    int r = 0;
    unsigned long bits;
    struct energy_header_disk *header;
	struct dm_io_region where;

    locate_header(&where, ec, idisk);
    header = (struct energy_header_disk*)vmalloc(where.count << SECTOR_SHIFT);
    if (!header) {
        DMERR("dump_header: Unable to allocate memory");
        return -ENOMEM;
    }

    header_to_disk(&(ec->header), header);
    r = dm_io_sync_vm(1, &where, WRITE, header, &bits, ec);
    if (r < 0) {
        DMERR("dump_header: Fail to write metadata header");
    }

    vfree(header);
    return r;
}

static int sync_table(struct energy_c *ec, struct vextent_disk *extents, 
        unsigned idisk, int rw)
{
    int r;
    unsigned long bits;
	struct dm_io_region where;
    sector_t index, offset, size = table_size(ec);
    void *data = (void*)extents;

    where.bdev = ec->disks[idisk].dev->bdev;
    offset = (ec->disks[idisk].capacity << ec->ext_shift) + header_size();
    for (index = 0; index < size; index += where.count) {
        where.sector = offset + index;
        where.count = (size - index) < MAX_SECTORS 
            ? (size - index) : MAX_SECTORS;
        r = dm_io_sync_vm(1, &where, rw, data, &bits, ec); 
        if (r < 0) {
            DMERR("sync_table: Unable to sync table");
            vfree(extents);
            return r;
        }
        data += (where.count << SECTOR_SHIFT);
    }

    return 0;
}

/*
 * Dump metadata to all disks.
 */
static int dump_metadata(struct energy_c *ec)
{
    int r;
    unsigned i;
    struct vextent_disk *extents;

    extents = (struct vextent_disk*)vmalloc(table_size(ec));
    if (!extents) {
        DMERR("dump_metadata: Unable to allocate memory");
        return -ENOMEM;
    }

    for (i = 0; i < vdisk_size(ec); ++i)
        extent_to_disk(ec->table + i, extents + i);

    for (i = 0; i < fdisk_nr(ec); ++i) {
        r = dump_header(ec, i);
        if (r < 0) {
            DMERR("dump_metadata: Fail to dump header to disk %u", i);
            return r;
        }
        r = sync_table(ec, extents, i, WRITE);
        if (r < 0) {
            DMERR("dump_metadata: Fail to dump table to disk %u", i);
            return r;
        }
    }

    vfree(extents);
    return 0;
}

/*
 * Check metadata header from a disk.
 */
static int check_header(struct energy_c *ec, unsigned idisk)
{
    int r = 0;
    unsigned long bits;
    struct energy_header_disk *ehd;
    struct energy_header header;
	struct dm_io_region where;

    locate_header(&where, ec, idisk);
    ehd = (struct energy_header_disk*)vmalloc(where.count << SECTOR_SHIFT);
    if (!ehd) {
		DMERR("check_header: Unable to allocate memory");
        return -ENOMEM;
    }

    r = dm_io_sync_vm(1, &where, READ, ehd, &bits, ec);
    if (r < 0) {
        DMERR("check_header: dm_io failed when reading metadata");
        goto exit_check;
    }

    header_from_disk(&header, ehd);
    if (header.magic != ec->header.magic 
            || header.version != ec->header.version
            || header.ndisk != ec->header.ndisk
            || header.ext_size != ec->header.ext_size
            || header.capacity != ec->header.capacity) {
        DMERR("check_header: Metadata header dismatch");
        r = -EINVAL;
        goto exit_check;
    }

exit_check:
    vfree(ehd);
    return r;
}

static int alloc_table(struct energy_c *ec, bool zero)
{
    size_t size = vdisk_size(ec) * sizeof(struct vextent);

    ec->table = (struct vextent*)vmalloc(size);
    if (!(ec->table)) {
        DMERR("alloc_table: Unable to allocate memory");
        return -ENOMEM;
    }
    if (zero) {
        memset(ec->table, 0, size);
    }
    DMDEBUG("alloc_table: table created");

    return 0;
}

/*
 * Load metadata, which is saved in each disk right after extents data. 
 * Metadata format: <header> [<eid> <state> <counter>]+
 */
static int load_metadata(struct energy_c *ec)
{
    int r;
    unsigned i;
    struct vextent_disk *extents;

    r = alloc_table(ec, false);
    if (r < 0)
        return r;

    extents = (struct vextent_disk*)vmalloc(table_size(ec));
    if (!extents) {
        DMERR("load_metadata: Unable to allocate memory");
        r = -ENOMEM;
        goto bad_extents;
    }

    /* Load table from 1st disk, which is considered as prime disk */
    r = sync_table(ec, extents, 0, READ);
    if (r < 0) 
        goto bad_sync;

    for (i = 0; i < vdisk_size(ec); ++i) { 
        extent_from_disk(ec->table + i, extents + i);
        if (ec->table[i].state & VES_PRESENT) { 
            DMDEBUG("mapping: %d -> %llu", i, ec->table[i].eid);
        }
    }

    vfree(extents);
    return 0;

bad_sync:
    vfree(extents);
bad_extents:
    vfree(ec->table);
    ec->table = NULL;
    return r;
}

static int build_bitmap(struct energy_c *ec, bool zero)
{
    extent_t i; 
    unsigned j, k, size = bitmap_size(vdisk_size(ec));
    
    ec->bitmap = (unsigned long *)vmalloc(size);
    if (!ec->bitmap) {
        DMERR("build_bitmap: Unable to allocate memory");
        return -ENOMEM;
    }

    memset(ec->bitmap, 0, size);
    if (zero) {
        for (j = 0; j < fdisk_nr(ec); ++j)
            ec->disks[j].free_nr = ec->disks[j].capacity;
    } else {
        i = 0;
        for (j = 0; j < fdisk_nr(ec); ++j) {
            ec->disks[j].free_nr = ec->disks[j].capacity;
            for (k = 0; k < ec->disks[j].capacity; ++k) {
                if (ec->table[i].state & VES_PRESENT) {
                    bitmap_set(ec->bitmap, i, 1);
                    ec->disks[j].free_nr--;
                    DMDEBUG("extent %llu is present", i);
                }
                ++i;
            }
        }
        BUG_ON(i != vdisk_size(ec));
        /*
        j = 0;
        k = ec->disks[j].capacity;
        ec->disks[j].free_nr = k;
        for (i = 0; i < vdisk_size(ec); ++i) {
            if (k == 0) { 
                DMDEBUG("free extent on disk %lu: %llu", 
                        j, ec->disks[j].free_nr);
                k = ec->disks[++j].capacity;
                ec->disks[j].free_nr = k;
            }
            if (ec->table[i].state & VES_PRESENT) {
                bitmap_set(ec->bitmap, i, 1);
                ec->disks[j].free_nr--;
                DMDEBUG("extent %d is present", i);
            }
            --k;
        }
        */
    }

    for (j = 0; j < fdisk_nr(ec); ++j) {
        DMDEBUG("free extent on disk %d: %llu", j, ec->disks[j].free_nr);
    }

    return 0;
}

static void clear_table(struct energy_c *ec)
{
    unsigned i;

    for (i = 0; i < vdisk_size(ec); ++i) 
        ec->table[i].state &= ~VES_ACCESS;
}

/*
 * Map virtual extent 'veid' to physcial extent 'eid'.
 */
static void map_extent(struct energy_c *ec, extent_t veid, extent_t eid)
{
    ec->table[veid].eid = eid;
    ec->table[veid].state |= VES_PRESENT;
    if (on_prime(ec, eid)) {
        ec->prime_extents[eid].vext = ec->table + veid;
    }
}

/*
 * Map bio's request onto physcial extent eid.
 */
static void map_bio(struct energy_c *ec, struct bio *bio, extent_t eid)
{
    unsigned idisk;
    sector_t offset;          /* sector offset within extent */

    offset = (bio->bi_sector & (extent_size(ec) - 1));
    extent_on_disk(ec, &eid, &idisk);
    bio->bi_bdev = ec->disks[idisk].dev->bdev;
    bio->bi_sector = (eid << ec->ext_shift) + offset;
    /* Limit IO within an extent as it is fine to get less than wanted. */
    bio->bi_size = min(bio->bi_size, to_bytes(extent_size(ec) - offset));
}

struct promote_info {
    struct energy_c *ec;
    struct bio      *bio;   /* bio to submit after migration */
    extent_t        veid;   /* virtual extent to promote */
    extent_t        peid;   /* destinate prime extent of the promotion */
};

/*
 * Callback of promote_extent. It should release resources allocated by
 * promote_extent properly upon either success or failure.
 */
static void promote_callback(int read_err, unsigned long write_err,
        void *context)
{
    struct promote_info *pinfo = (struct promote_info *)context;

    if (read_err || write_err) {
		if (read_err)
			DMERR("promote_callback: Read error.");
		else
			DMERR("promote_callback: Write error.");
        /* undo promote */
        spin_lock(&(pinfo->ec->lock));
        put_prime(pinfo->ec, pinfo->peid);
        spin_unlock(&(pinfo->ec->lock));
    } else { 
        /* update new mapping */
        DMDEBUG("promote: extent %llu is remapped to extent %llu", 
                pinfo->veid, pinfo->peid);
        spin_lock(&(pinfo->ec->lock));
        put_extent(pinfo->ec, pinfo->ec->table[pinfo->veid].eid);
        pinfo->ec->table[pinfo->veid].eid = pinfo->peid;
        spin_unlock(&(pinfo->ec->lock));
        /* resubmit bio */
        map_bio(pinfo->ec, pinfo->bio, pinfo->peid);
		generic_make_request(pinfo->bio);
    }

    kfree(pinfo);
}

/*
 * Promote virtual extent 'veid'. This function returns immediately, but it
 * might schedule delayed operation and callback. Upon any failure, it
 * simply gives up. 
 */
static bool promote_extent(struct energy_c *ec, struct bio *bio)
{
    struct dm_io_region src, dst;
    extent_t veid, peid, eid;
    unsigned idisk;
    struct promote_info *pinfo;

    if (get_prime(ec, &peid) < 0) { 
        DMDEBUG("promote_extent: no extent on prime disk");
        return false;        /* no free prime extent */
    }

    /* use GFP_ATOMIC because it is holding a spinlock */
    pinfo = (struct promote_info *)kmalloc(
            sizeof(struct promote_info), GFP_ATOMIC);
    if (!pinfo) {
        DMERR("promote_extent: Could not allocate memory");
        return false;        /* out of memory */
    }

    veid = ((bio->bi_sector) >> ec->ext_shift);
    eid = ec->table[veid].eid;
    extent_on_disk(ec, &eid, &idisk);
    src.bdev = ec->disks[idisk].dev->bdev;
    src.sector = eid << ec->ext_shift;
    src.count = extent_size(ec);

    dst.bdev = ec->disks[PRIME_DISK].dev->bdev;
    dst.sector = peid << ec->ext_shift;
    dst.count = extent_size(ec);

    pinfo->ec = ec;
    pinfo->bio = bio;
    pinfo->veid = veid;
    pinfo->peid = peid;

    dm_kcopyd_copy(ec->kcp_client, &src, 1, &dst, 0, 
            (dm_kcopyd_notify_fn)promote_callback, pinfo);

    return true;
}

struct demote_info {
    struct energy_c *ec;
    struct extent   *pext;
    extent_t        seid;
    extent_t        deid;
};

static void demote_callback(int read_err, unsigned long write_err, 
        void *context)
{
    struct demote_info *dinfo = (struct demote_info *)context;
    struct energy_c *ec;
    struct extent *ext;
    extent_t seid, deid;
    bool run_low = false;

    ec = dinfo->ec;
    ext = dinfo->pext;
    seid = dinfo->seid;
    deid = dinfo->deid;
    if (read_err || write_err) {
		if (read_err)
			DMERR("promote_callback: Read error.");
		else
			DMERR("promote_callback: Write error.");
        /* undo demote */
        spin_lock(&dinfo->ec->lock);
        ext->vext->state &= ~VES_MIGRATE;
        list_add(&ext->list, &ec->prime_use);
        put_extent(ec, deid);
        spin_unlock(&dinfo->ec->lock);
    } else {
        DMDEBUG("demote: extent %u is remapped to extent %llu", 
                (ext->vext - ec->table)/sizeof(struct vextent), deid);
        spin_lock(&dinfo->ec->lock);
        ext->vext->state &= ~VES_MIGRATE;
        ext->vext->eid = deid;
        ext->vext = NULL;
        put_extent(ec, seid);
        run_low = (ec->disks[PRIME_DISK].free_nr < EXTENT_FREE);
        spin_unlock(&dinfo->ec->lock);
    }
    kfree(dinfo);

    /* schedule more eviction 
    if (run_low) 
        queue_work(kenergyd_wq, &ec->eviction_work);
    */
}

/*
 * Demote extents using WSClock-LRU algorithm.
 */
static void demote_extent(struct energy_c *ec)
{
    struct dm_io_region src, dst;
    struct extent *next, *ext = ec->eviction_cursor;
    extent_t seid, deid;
    unsigned idisk;
    struct demote_info *dinfo;

    if (!ext) { 
        DMDEBUG("demote_extent: Nothing to demote");
        return ;
    }

    dinfo = kmalloc(sizeof(struct demote_info), GFP_KERNEL);
    if (!dinfo) {
        DMDEBUG("demote_extent: Could not allocate memory");
        return ;
    }

    spin_lock(&ec->lock);
    while (ext->vext->state & (VES_ACCESS | VES_MIGRATE)) { 
        ext->vext->state &= ~VES_ACCESS;    /* clear access bit */
        ext = next_extent(ext);
        if (ext == ec->eviction_cursor) {   /* end of iteration */ 
            spin_unlock(&ec->lock);
            return ;
        }
    }
    if (get_extent(ec, &deid, false) < 0) { /* no space on disk */
        spin_unlock(&ec->lock);
        return ;
    }
    seid = ext->vext->eid;
    ext->vext->state |= VES_MIGRATE;
    next = next_extent(ext);
    list_del(&ext->list);
    ec->eviction_cursor = (ext == next) ? NULL : next;
    spin_unlock(&ec->lock);

    BUG_ON(!on_prime(ec, seid) || on_prime(ec, deid));
    src.bdev = ec->disks[PRIME_DISK].dev->bdev;
    src.sector = seid << ec->ext_shift;
    src.count = extent_size(ec);

    extent_on_disk(ec, &deid, &idisk);
    dst.bdev = ec->disks[idisk].dev->bdev;
    dst.sector = deid << ec->ext_shift;
    dst.count = extent_size(ec);

    dinfo->ec = ec;
    dinfo->pext = ext;
    dinfo->seid = seid;
    dinfo->deid = deid;
    dm_kcopyd_copy(ec->kcp_client, &src, 1, &dst, 0,
            (dm_kcopyd_notify_fn)demote_callback, dinfo);
}

static void eviction_work(struct work_struct *work)
{
    struct energy_c *ec;

    ec = container_of(work, struct energy_c, eviction_work);
    if (ec->eviction_cursor == NULL && !list_empty(&ec->prime_use)) { 
        ec->eviction_cursor = list_first_entry(&ec->prime_use, 
                struct extent, list);
        DMDEBUG("eviction_work: unintialized cursor %llu", 
                ec->eviction_cursor->vext->eid);
    }
    DMDEBUG("eviction_work: %llu", vdisk_size(ec));
    /*
    if (ec->eviction_cursor != NULL) { 
        DMDEBUG("eviction_work: evicting %lu", 
                (ec->eviction_cursor->vext - ec->table)/sizeof(struct vextent));
    }
    demote_extent(ec);
    */
}

/*
 * Build LRU list and free list of extents on prime disk.
 */
static int build_prime(struct energy_c *ec)
{
    size_t size; 
    extent_t eid, veid;

    size = sizeof(struct extent) * prime_size(ec);
    ec->prime_extents = (struct extent *)vmalloc(size);
    if (!ec->prime_extents) {
        DMERR("build_prime: Unable to allocate memory");
        return -ENOMEM;
    }
    memset(ec->prime_extents, 0, size);

    INIT_LIST_HEAD(&ec->prime_free);
    for (eid = 0; eid < prime_size(ec); ++eid) {
        list_add(&(ec->prime_extents[eid].list), &ec->prime_free);
    }

    INIT_LIST_HEAD(&ec->prime_use);
    for (veid = 0; veid < vdisk_size(ec); ++veid) {
        if (!(ec->table[veid].state & VES_PRESENT))
            continue;
        eid = ec->table[veid].eid;
        if (on_prime(ec, eid)) { 
            ec->prime_extents[eid].vext = ec->table + veid;
            list_del(&(ec->prime_extents[eid].list));
            list_add(&(ec->prime_extents[eid].list), &ec->prime_use);
            DMDEBUG("build_prime: prime extent %llu is in use", eid);
        }
    }

    return 0;
}

/*
 * Construct an energy mapping.
 *  <extent size> <number of disks> [<dev> <number-of-extent>]+
 */
static int energy_ctr(struct dm_target *ti, unsigned int argc, char **argv)
{
    uint32_t ndisk;
    uint32_t ext_size;
	char *end;
    struct energy_c *ec;
    int r;

    DMDEBUG("energy_ctr (argc: %d)", argc);

    if (argc < 4) {
        ti->error = "Not enough arguments";
        return -EINVAL;
    }

	ext_size = simple_strtoul(argv[0], &end, 10);
	if (*end || !is_power_of_2(ext_size) 
            || (ext_size < (PAGE_SIZE >> SECTOR_SHIFT))) {
		ti->error = "Invalid extent size";
		return -EINVAL;
	}

    if (ti->len & (ext_size -1)) {
        ti->error = "Target length not divisible by extent size";
        return -EINVAL;
    }

    ndisk = simple_strtoul(argv[1], &end, 10);
    if (!ndisk || *end) {
        ti->error = "Invalid disk number";
        return -EINVAL;
    }

    if (argc != (2 + 2*ndisk)) {
        ti->error = "Number of parameters mismatch";
        return -EINVAL;
    }

    ec = alloc_context(ti, ndisk, ext_size);
    if (!ec) {
        ti->error = "Fail to allocate memory for energy context";
        return -ENOMEM;
    }
    DMDEBUG("extent size: %u;  extent shift: %u", ext_size, ec->ext_shift);

    r = get_disks(ec, argv+2);
    if (r < 0) {
        ti->error = "Fail to get mapped disks";
        goto bad_disks;
    }

    ec->io_client = dm_io_client_create();
    if (IS_ERR(ec->io_client)) {
		r = PTR_ERR(ec->io_client);
        ti->error = "Fail to create dm_io_client";
        goto bad_io_client;
    }

    ec->kcp_client = dm_kcopyd_client_create();
    if (IS_ERR(ec->kcp_client)) {
		r = PTR_ERR(ec->io_client);
        ti->error = "Fail to create dm_io_client";
        goto bad_kcp_client;
    }

    r = check_header(ec, 0);
    if (r < 0) {
        DMDEBUG("no useable metadata on disk");
        r = alloc_table(ec, true);
        if (r < 0) {
            ti->error = "Fail to alloc table";
            goto bad_metadata;
        }
        r = build_bitmap(ec, true);
        if (r < 0) {
            ti->error = "Fail to build bitmap";
            goto bad_bitmap;
        }
    } else {
        DMDEBUG("loading metadata from disk");
        r = load_metadata(ec);
        if (r < 0) {
            ti->error = "Fail to load metadata";
            goto bad_metadata;
        }
        r = build_bitmap(ec, false);
        if (r < 0) {
            ti->error = "Fail to build bitmap";
            goto bad_bitmap;
        }
    }

    r = build_prime(ec);
    if (r < 0) {
        DMDEBUG("building prime extents");
        ti->error = "Fail to build prime extents";
        goto bad_prime;
    }

    clear_table(ec);
    INIT_WORK(&ec->eviction_work, eviction_work);

    return 0;

bad_prime:
    vfree(ec->bitmap);
    ec->bitmap = NULL;
bad_bitmap:
    vfree(ec->table);
    ec->table = NULL;
bad_metadata:
    dm_kcopyd_client_destroy(ec->kcp_client);
bad_kcp_client:
    dm_io_client_destroy(ec->io_client);
bad_io_client:
    put_disks(ec, ndisk);
bad_disks:
    free_context(ec);

    return r;
}

static void energy_dtr(struct dm_target *ti)
{
    struct energy_c *ec = (struct energy_c*)ti->private;

    DMDEBUG("energy_dtr");
    flush_workqueue(kenergyd_wq);
    if (dump_metadata(ec) < 0) 
        DMERR("Fail to dump metadata");

    dm_kcopyd_client_destroy(ec->kcp_client);
    dm_io_client_destroy(ec->io_client);
    put_disks(ec, fdisk_nr(ec));
    free_context(ec);
}

static int energy_map(struct dm_target *ti, struct bio *bio,
        union map_info *map_context)
{
    struct energy_c *ec = (struct energy_c*)ti->private;
    extent_t eid, veid = ((bio->bi_sector) >> ec->ext_shift);
    bool run_low;

    DMDEBUG("%lu: map(sector %llu -> extent %llu)%u", jiffies, 
            bio->bi_sector, veid, ec->ext_shift);

    spin_lock(&ec->lock);
    ec->table[veid].state |= VES_ACCESS;
    ec->table[veid].counter++;
    if (ec->table[veid].state & VES_PRESENT) {
        eid = ec->table[veid].eid;
        if (!on_prime(ec, eid) && promote_extent(ec, bio)) {
            spin_unlock(&ec->lock);
            return DM_MAPIO_SUBMITTED;      /* submit it after promote */
        }
    } else {
        BUG_ON(get_extent(ec, &eid, true) < 0);   /* out of space */
        map_extent(ec, veid, eid);
    }
    run_low = (ec->disks[PRIME_DISK].free_nr < EXTENT_LOW);
    spin_unlock(&ec->lock);

    map_bio(ec, bio, eid);

    if (run_low) {              /* schedule extent eviction */
        queue_work(kenergyd_wq, &ec->eviction_work);
    }

    return DM_MAPIO_REMAPPED;
}

static int energy_status(struct dm_target *ti, status_type_t type,
        char *result, unsigned int maxlen)
{
    unsigned i;
    extent_t free = 0;
    struct energy_c *ec = (struct energy_c *)ti->private;

    DMDEBUG("energy_status");
    switch(type) {
        case STATUSTYPE_INFO:
            result[0] = '\0';
            break;

        case STATUSTYPE_TABLE:
            for (i = 0; i < fdisk_nr(ec); ++i) 
                free += ec->disks[i].free_nr;
            snprintf(result, maxlen, "extent size: %u, capacity: %llu \
                    free prime extents: %llu, free extents: %llu",
                    extent_size(ec), vdisk_size(ec), 
                    ec->disks[PRIME_DISK].free_nr, free);
            break;
    }
    return 0;
}

static struct target_type energy_target = {
	.name	     = "energy",
	.version     = {0, 1, 0},
	.module      = THIS_MODULE,
	.ctr	     = energy_ctr,
	.dtr	     = energy_dtr,
	.map	     = energy_map,
	.status	     = energy_status,
};

static int __init energy_init(void)
{
    int r = 0;

    kenergyd_wq = create_workqueue(ENERGY_DAEMON);
    if (!kenergyd_wq) {
        DMERR("Couldn't start " ENERGY_DAEMON);
        goto bad_workqueue;
    }

	r = dm_register_target(&energy_target);
    if (r < 0) {
        DMERR("energy register failed %d\n", r);
        goto bad_register;
    }

    DMDEBUG("energy initialized");
    return r;

bad_register:
    destroy_workqueue(kenergyd_wq);
bad_workqueue:
    return r;
}

static void __exit energy_exit(void)
{
	dm_unregister_target(&energy_target);
    destroy_workqueue(kenergyd_wq);
}

module_init(energy_init);
module_exit(energy_exit);

MODULE_DESCRIPTION(DM_NAME " energy target");
MODULE_AUTHOR("Ming Chen <mchen@cs.stonybrook.edu>");
MODULE_LICENSE("GPL");
