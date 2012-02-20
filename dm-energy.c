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

#include <linux/device-mapper.h>

#define DM_MSG_PREFIX "energy"

#define array_too_big(fixed, obj, num) \
	((num) > (UINT_MAX - (fixed)) / (obj))

struct mapped_disk {
    struct dm_dev *dev;
    sector_t start;
    uint64_t ext_count;     /* number of extents */
    
    atomic_t err_count;     /* number of errors */
};

struct energy_c {
    uint32_t ndisk;
    uint32_t ext_size;
    uint64_t ext_count;

    uint32_t ext_shift;

    struct mapped_disk disks[0];
};

static struct energy_c *alloc_context(unsigned int ndisk)
{
    size_t len;

    if (array_too_big(sizeof(struct energy_c), 
                sizeof(struct mapped_disk), ndisk))
        return NULL;

    len = sizeof(struct energy_c) + (sizeof(struct mapped_disk) * ndisk);

    return kmalloc(len, GFP_KERNEL);
}

/*
 * Get a mapped disk
 */
static int get_mdisk(struct dm_target *ti, struct energy_c *ec, 
        unsigned idisk, char **argv)
{
    char *end;
    sector_t start, len;

    start = simple_strtoull(argv[1], &end, 10);
    if (*end) 
        return -EINVAL;
    ec->disks[idisk].start = start;

    ec->disks[idisk].ext_count = simple_strtoull(argv[2], &end, 10);
    if (*end)
        return -EINVAL;
    len = ec->disks[idisk].ext_count << ec->ext_shift;

    if (dm_get_device(ti, argv[0], dm_table_get_mode(ti->table), 
                start, len, &ec->disks[idisk].dev))
        return -ENXIO;

    return 0;
}

/*
 * Construct an energy mapping.
 *  <extent size> <number of disks> [<dev> <offset> <length>]+
 */
static int energy_ctr(struct dm_target *ti, unsigned int argc, char **argv)
{
    uint32_t ndisk;
    uint32_t extent_size;
	char *end;
    struct energy_c *ec;
    unsigned i;
    int r;

    DMERR("energy_ctr (argc: %d)\n", argc);

    if (argc < 5) {
        ti->error = "Not enough arguments";
        return -EINVAL;
    }

	extent_size = simple_strtoul(argv[0], &end, 10);
	if (*end || !is_power_of_2(extent_size) 
            || (extent_size < (PAGE_SIZE >> SECTOR_SHIFT))) {
		ti->error = "Invalid extent size";
		return -EINVAL;
	}

    if (ti->len & (extent_size -1)) {
        ti->error = "Target length not divisible by extent size";
        return -EINVAL;
    }

    ndisk = simple_strtoul(argv[1], &end, 10);
    if (!ndisk || *end) {
        ti->error = "Invalid disk number";
        return -EINVAL;
    }

    if (argc != (2 + 3*ndisk)) {
        ti->error = "Disk parameters not match disk count";
        return -EINVAL;
    }

    ec = alloc_context(ndisk);
    if (!ec) {
        ti->error = "Memory allocation for energy context failed";
        return -ENOMEM;
    }

    ec->ndisk = ndisk;
    ec->ext_size = extent_size;
    ec->ext_count = 0;
    ec->ext_shift = ffs(extent_size) - 1;

    for (i = 0, argv += 2; i < ndisk; ++i, argv += 2) {
        r = get_mdisk(ti, ec, i, argv);
        if (r < 0) {
            ti->error = "Cannot parse mapped disk";
            while (i--)
                dm_put_device(ti, ec->disks[i].dev);
            kfree(ec);
            return r;
        }
        atomic_set(&(ec->disks[i].err_count), 0);
        ec->ext_count += ec->disks[i].ext_count;
    }

    if (ti->len != (ec->ext_count << ec->ext_shift)) {
        for (i = 0; i < ndisk; ++i)
            dm_put_device(ti, ec->disks[i].dev);
        kfree(ec);
        ti->error = "Disk length mismatch";
        return -EINVAL;
    }

    ti->private = ec;

    return 0;
}

static void energy_dtr(struct dm_target *ti)
{
    int i;
    struct energy_c *ec = (struct energy_c*)ti->private;

    DMERR("energy_dtr\n");
    for (i = 0; i < ec->ndisk; ++i)
        dm_put_device(ti, ec->disks[i].dev);

    kfree(ec);
}

static int energy_map(struct dm_target *ti, struct bio *bio,
        union map_info *map_context)
{
    DMDEBUG("energy_map\n");
    return DM_MAPIO_REMAPPED;
}

static int energy_status(struct dm_target *ti, status_type_t type,
			 char *result, unsigned int maxlen)
{
    DMDEBUG("energy_status\n");
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

    DMERR("energy initied\n");
	r = dm_register_target(&energy_target);
    if (r < 0) {
        DMERR("energy register failed %d\n", r);
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
