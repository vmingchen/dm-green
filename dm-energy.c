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
#include <linux/bitmap.h>
#include <linux/jiffies.h>

#include <linux/device-mapper.h>

#define DM_MSG_PREFIX "energy"

/*
 * Magic for persistent energy header: "EnEg"
 */
#define ENERGE_MAGIC 0x45614567
#define ENERGE_VERSION 1

#define SECTOR_SIZE (1 << SECTOR_SHIFT)

#define array_too_big(fixed, obj, num) \
	((num) > (UINT_MAX - (fixed)) / (obj))

/*
 * Header on disk, followed by metadata for mapped_disk and energy_map_entry.
 */
struct energy_header_disk {
    __le32 magic;
    __le32 version;
    __le32 ndisk;
    __le32 ext_size;
    __le64 ext_count;
} __packed;

/*
 * Header in memory, contained in energy context (energy_c).
 */
struct energy_header_core {
    uint32_t magic;
    uint32_t version;
    uint32_t ndisk;
    uint32_t ext_size;
    uint64_t ext_count;
};

struct energy_map_entry {
    uint64_t mapped_id;
    uint32_t flags;
    uint32_t freq;              /* how many times are accessed */
};

struct energy_extent {
    struct energy_map_entry entry;
    uint64_t tick;              /* timestamp of latest access */
    atomic_t ref_count;
};

struct mapped_disk {
    struct dm_dev *dev;
    uint64_t ext_count;         /* number of extents */
    uint64_t ext_free;          /* number of free extents */
    atomic_t err_count;         /* number of errors */
};

struct energy_c {
    struct dm_target *ti;

    struct energy_header_core header;
    uint32_t flags;
    uint32_t ext_shift;

    struct mapped_disk *disks;
    struct energy_extent *table;
    unsigned long *bitmap;      /* bitmap of extent, '0' for free extent */

    struct dm_io_client *io_client;
    struct dm_kcopyd_client *kcp_client;

    uint64_t migration_ext;     /* logical extent id under migration */
    uint64_t migration_src;     /* source physical extent id */
    uint64_t migration_dst;     /* dest physical extent id */
};

static struct energy_c *alloc_context(uint32_t ndisk)
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

    /* table and extent bitmap not allocated yet */
    ec->table = NULL;       
    ec->bitmap = NULL;      

    ec->io_client = NULL;
    ec->kcp_client = NULL;

    return ec;
}

static void free_context(struct energy_c *ec)
{
    BUG_ON(!ec || !(ec->disks));

    if (ec->table) {
        kfree(ec->table);
    }
    if (ec->bitmap) {
        kfree(ec->bitmap);
    }

    kfree(ec->disks);
    kfree(ec);
}

/*
 * Return size of on-disk metadata in sector
 */
static inline sector_t metadata_size(struct energy_c *ec) 
{
    uint64_t blk_count = sizeof(struct energy_header_core) 
            + ec->header.ext_count * sizeof(struct energy_map_entry);

    return (blk_count + (SECTOR_SIZE - 1)) >> SECTOR_SHIFT;
}

static void header_to_disk(struct energy_header_core *core, 
        struct energy_header_disk *disk)
{   
    disk->magic = cpu_to_le32(core->magic);
    disk->version = cpu_to_le32(core->version);
    disk->ndisk = cpu_to_le32(core->ndisk);
    disk->ext_size = cpu_to_le32(core->ext_size);
    disk->ext_count = cpu_to_le64(core->ext_count);
}

static void header_from_disk(struct energy_header_core *core,
        struct energy_header_disk *disk)
{   
    core->magic = le32_to_cpu(disk->magic);
    core->version = le32_to_cpu(disk->version);
    core->ndisk = le32_to_cpu(disk->ndisk);
    core->ext_size = le32_to_cpu(disk->ext_size);
    core->ext_count = le64_to_cpu(disk->ext_count);
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

    ec->disks[idisk].ext_count = simple_strtoull(argv[1], &end, 10);
    if (*end)
        return -EINVAL;

    len = ec->disks[idisk].ext_count << ec->ext_shift; 
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
    if (dev_size < len + metadata_size(ec)) 
        return -ENOSPC;

    return 0;
}

/*
 * Put all disk devices
 */
static void put_disks(struct energy_c *ec, int ndisk)
{
    int i;

    for (i = 0; i < ndisk; ++i) {
        dm_put_device(ec->ti, ec->disks[i].dev);
    }
}

/*
 * Get all disk devices
 */
static int get_disks(struct energy_c *ec, char **argv)
{
    int i, r;

    ec->header.ext_count = 0;
    for (i = 0; i < ec->header.ndisk; ++i, argv += 2) {
        r = get_mdisk(ec->ti, ec, i, argv);
        if (r < 0) {
            put_disks(ec, i);
            break;
        }
        atomic_set(&(ec->disks[i].err_count), 0);
        ec->header.ext_count += ec->disks[i].ext_count;
    }

    return r;
}

/*
 * Wrapper function for new dm_io API
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

/*
 * Load metadata, which is saved in each disk right after extents data. 
 * Metadata format: <header> [<energy_map_entry>]+
 */
static int load_metadata(struct energy_c *ec)
{
    int r = 0;
    unsigned long bits;
	struct dm_io_region where;
    struct energy_header_disk *header_disk;

    header_disk = (struct energy_header_disk*)vmalloc(SECTOR_SIZE);
    if (!header_disk) {
		DMERR("load_metadata: Unable to allocate memory");
        return -ENOMEM;
    }

    /* Read metadata from 1-st disk, which is taken as prime disk. */
    where.bdev = ec->disks[0].dev->bdev;
    // where.sector = ec->disks[0].ext_count << ec->ext_shift;
    where.sector = 0;
    where.count = 1;
    dm_io_sync_vm(1, &where, READ, header_disk, &bits, ec);

    /* Check */
    if (le32_to_cpu(header_disk->magic) != ENERGE_MAGIC) {
        DMDEBUG("Metadata dismatch (%u, %u), rewriting...", 
                header_disk->magic, le32_to_cpu(header_disk->magic));
        header_to_disk(&(ec->header), header_disk);
        dm_io_sync_vm(1, &where, WRITE, header_disk, &bits, ec);
        DMDEBUG("New metadata (%u) written", 
                le32_to_cpu(header_disk->magic));
    } else {
        DMDEBUG("Metadata match!");
    }

    vfree(header_disk);
    return r;
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

    ec = alloc_context(ndisk);
    if (!ec) {
        ti->error = "Memory allocation for energy context failed";
        return -ENOMEM;
    }

    ec->ti = ti;
    ec->header.magic = ENERGE_MAGIC;
    ec->header.version = ENERGE_VERSION;
    ec->header.ndisk = ndisk;
    ec->header.ext_size = ext_size;
    ec->ext_shift = ffs(ext_size) - 1;
    ti->private = ec;

    r = get_disks(ec, argv+2);
    if (r < 0) {
        ti->error = "Fail to get mapped disks";
        goto bad_disks;
    }

    if (ti->len != (ec->header.ext_count << ec->ext_shift)) {
        ti->error = "Disk length mismatch";
        r = -EINVAL;
        goto bad_io_client;
    }

    ec->io_client = dm_io_client_create();
    if (IS_ERR(ec->io_client)) {
		r = PTR_ERR(ec->io_client);
        ti->error = "Failed to create dm_io_client";
        goto bad_io_client;
    }

    ec->kcp_client = dm_kcopyd_client_create();
    if (IS_ERR(ec->kcp_client)) {
		r = PTR_ERR(ec->io_client);
        ti->error = "Failed to create dm_io_client";
        goto bad_kcp_client;
    }

    load_metadata(ec);

    return 0;

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

    DMDEBUG("energy_dtr\n");
    dm_kcopyd_client_destroy(ec->kcp_client);
    dm_io_client_destroy(ec->io_client);
    put_disks(ec, ec->header.ndisk);
    free_context(ec);
}

static int energy_map(struct dm_target *ti, struct bio *bio,
        union map_info *map_context)
{
    struct energy_c *ec = (struct energy_c*)ti->private;

    DMDEBUG("%lu: energy_map", jiffies);
    bio->bi_bdev = ec->disks[0].dev->bdev;
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

    DMDEBUG("energy initied\n");
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
