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
#include <linux/list.h>
#include <linux/jiffies.h>
#include <linux/spinlock.h>

#include <linux/device-mapper.h>

#define DM_MSG_PREFIX "energy"

/*
 * Magic for persistent energy header: "EnEg"
 */
#define ENERGE_MAGIC 0x45614567
#define ENERGE_VERSION 1

#define SECTOR_SIZE (1 << SECTOR_SHIFT)

#define count_sector(x) (((x) + SECTOR_SIZE - 1) >> SECTOR_SHIFT)

/* Return metadata's size in sector */
#define header_size() \
    count_sector(sizeof(struct energy_header_disk))

#define table_size(ec) \
    count_sector(ec->header.capacity * sizeof(struct extent_disk))

/* 
 * When requesting a new bio, the number of requested bvecs has to be
 * less than BIO_MAX_PAGES. Otherwise, null is returned. In dm-io.c,
 * this return value is not checked and kernel Oops may happen. We set
 * the limit here to avoid such situations. (2 additional bvecs are
 * required by dm-io for bookeeping.) (From dm-cache)
 */
#define MAX_SECTORS ((BIO_MAX_PAGES - 2) * (PAGE_SIZE >> SECTOR_SHIFT))

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

/* Extent states */
#define ES_PRESENT  0x01
#define ES_ACCESS   0x02
#define ES_MIGRATE  0x04

/*
 * Logical extent in memory.
 */
struct extent {
    extent_t eid;               /* physical extent id */
    uint32_t state;             
    uint32_t counter;           /* how many times are accessed */
    uint64_t tick;              /* timestamp of latest access */
    struct list_head list;      /* free extent list */
    spinlock_t lock;
};

/*
 * Extent metadata on disk.
 */
struct extent_disk {
    __le64 eid;
    __le32 state;
    __le32 counter;
} __packed;

struct mapped_disk {
    struct dm_dev *dev;
    extent_t capacity;          /* capacity in extent */
    extent_t free_nr;           /* number of free extents */
    struct list_head free_list; /* free extent on this disk */
    spinlock_t lock;            /* protect free_list and free_nr */
};

struct energy_c {
    struct dm_target *ti;

    struct energy_header header;
    uint32_t flags;
    uint32_t ext_shift;

    struct mapped_disk *disks;
    struct extent *table;       /* mapping table */
    spinlock_t lock;            /* protect table */

    struct dm_io_client *io_client;
    struct dm_kcopyd_client *kcp_client;

    extent_t migration_ext;     /* logical extent id under migration */
    extent_t migration_src;     /* source physical extent id */
    extent_t migration_dst;     /* dest physical extent id */
};

static struct energy_c *alloc_context(uint32_t ndisk, uint32_t ext_size)
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

    spin_lock_init(&ec->lock);

    ec->table = NULL;           /* table not allocated yet */
    ec->io_client = NULL;
    ec->kcp_client = NULL;

    return ec;
}

static void free_context(struct energy_c *ec)
{
    BUG_ON(!ec || !(ec->disks));

    if (ec->table) {
        vfree(ec->table);
        ec->table = NULL;
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

static inline void extent_to_disk(struct extent *core, 
        struct extent_disk *disk)
{
    disk->eid = cpu_to_le64(core->eid);
    disk->state = cpu_to_le32(core->state);
    disk->counter = cpu_to_le32(core->counter);
}

static inline void extent_from_disk(struct extent *core,
        struct extent_disk *disk)
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

    for (i = 0; i < ec->header.ndisk; ++i, argv += 2) {
        r = get_mdisk(ec->ti, ec, i, argv);
        if (r < 0) {
            put_disks(ec, i);
            break;
        }
        spin_lock_init(&(ec->disks[i].lock));
        ext_count += ec->disks[i].capacity;
    }

    /* Logical disk size should match sum of physical disks' size */
    if (ec->header.capacity != ext_count) {
        DMERR("Disk length dismatch");
        r = -EINVAL;
    }

    return r;
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

static int sync_table(struct energy_c *ec, unsigned idisk, int rw)
{
    int r;
    unsigned i;
    unsigned long bits;
	struct dm_io_region where;
    sector_t index, offset, size = table_size(ec);
    void *data;
    struct extent_disk *extents;

    extents = (struct extent_disk*)vmalloc(size);
    if (!extents) {
        DMERR("sync_table: Unable to allocate memory");
        return -ENOMEM;
    }

    if (rw == WRITE) {
        for (i = 0; i < ec->header.capacity; ++i)
            extent_to_disk(ec->table + i, extents + i);
    } 

    data = (void*)extents;
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

    if (rw == READ) {
        for (i = 0; i < ec->header.capacity; ++i) 
            extent_from_disk(ec->table + i, extents + i);
    }

    vfree(extents);
    return 0;
}

/*
 * Dump metadata to all disks.
 */
static int dump_metadata(struct energy_c *ec)
{
    unsigned i;
    int r;

    for (i = 0; i < ec->header.ndisk; ++i) {
        r = dump_header(ec, i);
        if (r < 0) {
            DMERR("dump_metadata: Fail to dump header to disk %u", i);
            return r;
        }
        r = sync_table(ec, i, WRITE);
        if (r < 0) {
            DMERR("dump_metadata: Fail to dump table to disk %u", i);
            return r;
        }
    }

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
    unsigned i;
    size_t size = ec->header.capacity * sizeof(struct extent);

    ec->table = (struct extent*)vmalloc(size);
    if (!(ec->table)) {
        DMERR("alloc_table: Unable to allocate memory");
        return -ENOMEM;
    }
    if (zero) {
        memset(ec->table, 0, size);
    }
    for (i = 0; i < ec->header.capacity; ++i) { 
        spin_lock_init(&(ec->table[i].lock));
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

    r = alloc_table(ec, false);
    if (r < 0)
        return r;

    /* Load table from 1st disk, which is considered as prime disk */
    r = sync_table(ec, 0, READ);
    if (r < 0) 
        goto bad_metadata;

    return 0;

bad_metadata:
    vfree(ec->table);
    ec->table = NULL;
    return r;
}

/*
 * Return physical disk id and offset of physical extent.
 */
static inline void extent_on_disk(struct energy_c *ec, extent_t *eid,
        unsigned *i)
{
    BUG_ON(*eid >= ec->header.capacity);
    *i = 0;
    while (*i < ec->header.ndisk && *eid >= ec->disks[*i].capacity) {
        *eid -= ec->disks[(*i)++].capacity;
    }
}

static void build_free_list(struct energy_c *ec)
{
    unsigned i;
    extent_t ei;
    struct extent *pext;
    struct list_head *head;

    pext = ec->table;
    for (i = 0; i < ec->header.ndisk; ++i) {
        DMDEBUG("Free extent on disk %u:", i);
        head = &(ec->disks[i].free_list);
        INIT_LIST_HEAD(head);
        ec->disks[i].free_nr = 0;
        for (ei = 0; ei < ec->disks[i].capacity; ++ei) {
            if (!(pext->state & ES_PRESENT)) { 
                list_add(&pext->list, head);
                DMDEBUG("%llu, ", ei);
                ec->disks[i].free_nr++;
            }
            ++pext;
        }
    }
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

    ec = alloc_context(ndisk, ext_size);
    if (!ec) {
        ti->error = "Fail to allocate memory for energy context";
        return -ENOMEM;
    }
    ec->ext_shift = ffs(ext_size) - 1;
    ec->header.magic = ENERGE_MAGIC;
    ec->header.version = ENERGE_VERSION;
    ec->header.ndisk = ndisk;
    ec->header.ext_size = ext_size;
    ec->header.capacity = (ti->len >> ec->ext_shift);
    ec->ti = ti;
    ti->private = ec;
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
    if (r) {
        DMDEBUG("no useable metadata on disk");
        r = alloc_table(ec, true);
        if (r < 0) {
            ti->error = "Fail to alloc table";
            goto bad_metadata;
        }
    } else {
        DMDEBUG("loading metadata from disk");
        r = load_metadata(ec);
        if (r < 0) {
            ti->error = "Fail to load metadata";
            goto bad_metadata;
        }
    }

    build_free_list(ec);

    return 0;

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
    if (dump_metadata(ec) < 0) 
        DMERR("Fail to dump metadata");

    dm_kcopyd_client_destroy(ec->kcp_client);
    dm_io_client_destroy(ec->io_client);
    put_disks(ec, ec->header.ndisk);
    free_context(ec);
}

static int energy_map(struct dm_target *ti, struct bio *bio,
        union map_info *map_context)
{
    struct energy_c *ec = (struct energy_c*)ti->private;
    uint64_t ext = ((bio->bi_sector) >> ec->ext_shift);

    DMDEBUG("%lu: map(sector %llu -> extent %llu)%u", jiffies, 
            bio->bi_sector, ext, ec->ext_shift);
    bio->bi_bdev = ec->disks[0].dev->bdev;
    ec->table[ext].state |= ES_PRESENT;
    return DM_MAPIO_REMAPPED;
}

static int energy_status(struct dm_target *ti, status_type_t type,
			 char *result, unsigned int maxlen)
{
    DMDEBUG("energy_status");
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
    int r;

    DMDEBUG("energy initied");
	r = dm_register_target(&energy_target);
    if (r < 0) {
        DMDEBUG("energy register failed %d\n", r);
    }

    return r;
}

static void __exit energy_exit(void)
{
	dm_unregister_target(&energy_target);
}

module_init(energy_init);
module_exit(energy_exit);

MODULE_DESCRIPTION(DM_NAME " energy target");
MODULE_AUTHOR("Ming Chen <mchen@cs.stonybrook.edu>");
MODULE_LICENSE("GPL");
