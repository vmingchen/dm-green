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

/*
 * Construct an energy mapping.
 *  <extent size> <number of disks> [<dev> <offset> <length>]+
 */
static int energy_ctr(struct dm_target *ti, unsigned int argc, char **argv)
{
    uint32_t extent_size;
	char *end;

    DMERR("energy_ctr (argc: %d)\n", argc);

    if (argc < 5) {
        ti->error = "Not enough arguments";
        return -EINVAL;
    }

	extent_size = simple_strtoul(argv[0], &end, 10);
	if (!is_power_of_2(extent_size) 
            || (extent_size < (PAGE_SIZE >> SECTOR_SHIFT))) {
		ti->error = "Invalid extent size";
		return -EINVAL;
	}

    return 0;
}

static void energy_dtr(struct dm_target *ti)
{
    DMERR("energy_dtr\n");
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

/*
static int energy_iterate_devices(struct dm_target *ti, 
        iterate_devices_callout_fn fn, void *data)
{
    int r = 0;
    return r;
}
*/

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
