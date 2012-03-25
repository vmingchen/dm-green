/*
 * Copyright (C) 2012, Ming Chen
 * 
 * A target to save energy by directing reads/writes to different physical
 * disks based on energy characteristics. 
 *
 * This file is released under the GPL.
 */
#include "dm-green.h"

static struct workqueue_struct *kgreend_wq;

static struct green_c *alloc_context(struct dm_target *ti, 
        uint32_t ndisk, uint32_t ext_size)
{
    struct green_c *gc;

    gc = kmalloc(sizeof(struct green_c), GFP_KERNEL);
    if (!gc)
        return gc;

    gc->disks = kmalloc(sizeof(struct mapped_disk) * ndisk, GFP_KERNEL);
    if (!gc->disks) {
        kfree(gc);
        return NULL;
    }

    gc->ti = ti;
    ti->private = gc;

    gc->ext_shift = ffs(ext_size) - 1;
    gc->header.magic = GREEN_MAGIC;
    gc->header.version = GREEN_VERSION;
    gc->header.ndisk = ndisk;
    gc->header.ext_size = ext_size;
    gc->header.capacity = (ti->len >> gc->ext_shift);

    spin_lock_init(&gc->lock);

    gc->table = NULL;           /* table not allocated yet */
    gc->io_client = NULL;
    gc->kcp_client = NULL;
    gc->prime_extents = NULL;
    gc->eviction_cursor = NULL;

    return gc;
}

static void free_context(struct green_c *gc)
{
    BUG_ON(!gc || !(gc->disks));

    if (gc->table) {
        vfree(gc->table);
        gc->table = NULL;
    }
    if (gc->bitmap) {
        vfree(gc->bitmap);
        gc->bitmap = NULL;
    }
    if (gc->prime_extents) {
        vfree(gc->prime_extents);
        gc->prime_extents = NULL;
    }

    kfree(gc->disks);
    kfree(gc);
}

static inline void header_to_disk(struct green_header *core, 
        struct green_header_disk *disk)
{   
    disk->magic = cpu_to_le32(core->magic);
    disk->version = cpu_to_le32(core->version);
    disk->ndisk = cpu_to_le32(core->ndisk);
    disk->ext_size = cpu_to_le32(core->ext_size);
    disk->capacity = cpu_to_le64(core->capacity);
}

static inline void header_from_disk(struct green_header *core,
        struct green_header_disk *disk)
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
static int get_mdisk(struct dm_target *ti, struct green_c *gc, 
        unsigned idisk, char **argv)
{
	sector_t dev_size;
    sector_t len;
    char *end;

    gc->disks[idisk].capacity = simple_strtoull(argv[1], &end, 10);
    if (*end)
        return -EINVAL;

    len = gc->disks[idisk].capacity << gc->ext_shift; 
#ifdef OLD_KERNEL
    if (dm_get_device(ti, argv[0], dm_table_get_mode(ti->table), 0, 
                len, &gc->disks[idisk].dev))
#else
    if (dm_get_device(ti, argv[0], dm_table_get_mode(ti->table), 
                &gc->disks[idisk].dev))
#endif
        return -ENXIO;

    /* device capacity should be large enough for extents and metadata */
    dev_size = gc->disks[idisk].dev->bdev->bd_inode->i_size >> SECTOR_SHIFT;
    if (dev_size < len + header_size() + table_size(gc)) 
        return -ENOSPC;

    return 0;
}

/*
 * Put disk devices.
 */
static void put_disks(struct green_c *gc, int ndisk)
{
    int i;

    for (i = 0; i < ndisk; ++i) {
        dm_put_device(gc->ti, gc->disks[i].dev);
    }
}

/*
 * Get all disk devices and check if disk size matches.
 */
static int get_disks(struct green_c *gc, char **argv)
{
    int r = 0;
    unsigned i;
    extent_t ext_count = 0;

    for (i = 0; i < fdisk_nr(gc); ++i, argv += 2) {
        r = get_mdisk(gc->ti, gc, i, argv);
        if (r < 0) {
            put_disks(gc, i);
            break;
        }
        gc->disks[i].offset = ext_count;
        ext_count += gc->disks[i].capacity;
    }

    /* Virtual disk size should match sum of physical disks' size */
    if (vdisk_size(gc) != ext_count) {
        DMERR("Disk length dismatch");
        r = -EINVAL;
    }

    return r;
}

/*
 * Check if physical extent 'ext' is on prime disk.
 */
static inline bool on_prime(struct green_c *gc, extent_t eid)
{
    return eid < prime_size(gc);
}

/*
 * Return physical extent id from extent pointer.
 */
static inline extent_t ext2id(struct green_c *gc, struct extent *ext)
{
    return (ext - gc->prime_extents);
}

/*
 * Return virtual extent id from vextent pointer.
 */
static inline extent_t vext2id(struct green_c *gc, struct vextent *vext)
{
    return (vext - gc->table);
}

/*
 * Return physical disk id and offset of physical extent.
 */
static inline void extent_on_disk(struct green_c *gc, extent_t *eid,
        unsigned *i)
{
    BUG_ON(*eid >= vdisk_size(gc));
    *i = 0;
    while (*i < fdisk_nr(gc) && *eid >= gc->disks[*i].capacity) {
        *eid -= gc->disks[(*i)++].capacity;
    }
}

/*
 * Return the extent next to 'ext' in a *non-empty* list. 
 * Note the next extent can be itself if there is only one extent.
 */
static inline struct extent *next_extent(struct list_head *head, 
        struct extent *ext)
{
    return (ext->list.next != head)
        ? list_entry(ext->list.next, struct extent, list)
        : list_first_entry(head, struct extent, list);
}

/*
 * Return the previous extent in a *non-empty* list.
 */
static inline struct extent *prev_extent(struct list_head *head,
        struct extent *ext)
{
    return (ext->list.prev != head)
        ? list_entry(ext->list.prev, struct extent, list)
        : list_entry(head->prev, struct extent, list);
}

/*
 * Get a prime extent.
 */
static inline int get_prime(struct green_c *gc, extent_t *eid)
{
    struct extent *first;

    if (list_empty(&gc->prime_free)) 
        return -ENOSPC;

    first = list_first_entry(&(gc->prime_free), struct extent, list);
    list_del(&first->list);
    list_add(&first->list, &gc->prime_use);
    *eid = ext2id(gc, first);

    gc->disks[PRIME_DISK].free_nr--;

#ifdef OLD_KERNEL
    *gc->bitmap = *gc->bitmap | (unsigned long)(1<<*eid); 
#else
    bitmap_set(gc->bitmap, *eid, 1);
#endif

    DMDEBUG("get_prime: get %llu (%llu extents left)", 
            *eid, gc->disks[PRIME_DISK].free_nr);

    return 0;
}

/*
 * Put a prime extent.
 */
static inline void put_prime(struct green_c *gc, extent_t eid)
{
    struct extent *ext;

    BUG_ON(eid >= prime_size(gc));
    ext = gc->prime_extents + eid;
    ext->vext = NULL;
    list_del(&ext->list);
    list_add(&ext->list, &(gc->prime_free));
    gc->disks[PRIME_DISK].free_nr++;

#ifdef OLD_KERNEL
    *gc->bitmap = *gc->bitmap & (unsigned long)(~(1<<eid)); 
#else
    bitmap_clear(gc->bitmap, eid, 1);
#endif

    DMDEBUG("put_prime: %llu prime extents left", gc->disks[PRIME_DISK].free_nr);
}

/*
 * Get a physical extent. 
 */
static int get_extent(struct green_c *gc, extent_t *eid, bool prime)
{
    unsigned i;

    if (prime && get_prime(gc, eid) == 0) 
        return 0;

    for (i = PRIME_DISK+1; i < fdisk_nr(gc); ++i) {
        if (gc->disks[i].free_nr > 0) {
            *eid = find_next_zero_bit(gc->bitmap, vdisk_size(gc), 
                    gc->disks[i].offset);
            DMDEBUG("get_extent: %llu obtained", *eid);
            gc->disks[i].free_nr--;
#ifdef OLD_KERNEL
	    *gc->bitmap = *gc->bitmap | (unsigned long)(1<<*eid); 
#else
            bitmap_set(gc->bitmap, *eid, 1);
#endif
            return 0;
        }
    }

    return -ENOSPC;
}

/*
 * Put a physcial extent.
 */
static void put_extent(struct green_c *gc, extent_t eid)
{
    unsigned i;

    BUG_ON(eid >= vdisk_size(gc));
    for (i = 0; eid >= gc->disks[i].capacity + gc->disks[i].offset; ++i)
        ;

    if (i == PRIME_DISK) {   /* prime disk */
        put_prime(gc, eid);
    } else { 
        gc->disks[i].free_nr++;
#ifdef OLD_KERNEL
        *gc->bitmap = *gc->bitmap & (unsigned long)(~(1<<eid)); 
#else
        bitmap_clear(gc->bitmap, eid, 1);
#endif
    }
}

/*
 * Wrapper function for new dm_io API.
 */
static int dm_io_sync_vm(unsigned num_regions, struct dm_io_region *where,
        int rw, void *data, unsigned long *error_bits, struct green_c *gc)
{
	struct dm_io_request iorq;

	iorq.bi_rw= rw;
	iorq.mem.type = DM_IO_VMA;
	iorq.mem.ptr.vma = data;
	iorq.notify.fn = NULL;
	iorq.client = gc->io_client;

	return dm_io(&iorq, num_regions, where, error_bits);
}

static inline void locate_header(struct dm_io_region *where, 
        struct green_c *gc, unsigned idisk)
{
    where->bdev = gc->disks[idisk].dev->bdev;
    where->sector = gc->disks[idisk].capacity << gc->ext_shift;
    where->count = header_size();
    BUG_ON(where->count > MAX_SECTORS);
}

/*
 * Dump metadata header to a disk.
 */
static int dump_header(struct green_c *gc, unsigned idisk)
{
    int r = 0;
    unsigned long bits;
    struct green_header_disk *header;
	struct dm_io_region where;

    locate_header(&where, gc, idisk);
    header = (struct green_header_disk*)vmalloc(where.count << SECTOR_SHIFT);
    if (!header) {
        DMERR("dump_header: Unable to allocate memory");
        return -ENOMEM;
    }

    header_to_disk(&(gc->header), header);
    r = dm_io_sync_vm(1, &where, WRITE, header, &bits, gc);
    if (r < 0) {
        DMERR("dump_header: Fail to write metadata header");
    }

    vfree(header);
    return r;
}

static int sync_table(struct green_c *gc, struct vextent_disk *extents, 
        unsigned idisk, int rw)
{
    int r;
    unsigned long bits;
	struct dm_io_region where;
    sector_t index, offset, size = table_size(gc);
    void *data = (void*)extents;

    where.bdev = gc->disks[idisk].dev->bdev;
    offset = (gc->disks[idisk].capacity << gc->ext_shift) + header_size();
    for (index = 0; index < size; index += where.count) {
        where.sector = offset + index;
        where.count = (size - index) < MAX_SECTORS 
            ? (size - index) : MAX_SECTORS;
        r = dm_io_sync_vm(1, &where, rw, data, &bits, gc); 
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
static int dump_metadata(struct green_c *gc)
{
    int r;
    unsigned i;
    extent_t veid;
    struct vextent_disk *extents;

    extents = (struct vextent_disk *)vmalloc(table_size(gc));
    if (!extents) {
        DMERR("dump_metadata: Unable to allocate memory");
        return -ENOMEM;
    }

    for (veid = 0; veid < vdisk_size(gc); ++veid) { 
        extent_to_disk(gc->table + veid, extents + veid);
        if (gc->table[veid].state & VES_PRESENT) { 
            DMDEBUG("dump_metadata: %llu -> %llu (%llu)", veid, 
                    le64_to_cpu(extents[veid].eid), gc->table[veid].eid);
        }
    }

    for (i = 0; i < fdisk_nr(gc); ++i) {
        r = dump_header(gc, i);
        if (r < 0) {
            DMERR("dump_metadata: Fail to dump header to disk %u", i);
            return r;
        }
        r = sync_table(gc, extents, i, WRITE);
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
static int check_header(struct green_c *gc, unsigned idisk)
{
    int r = 0;
    unsigned long bits;
    struct green_header_disk *ehd;
    struct green_header header;
	struct dm_io_region where;

    locate_header(&where, gc, idisk);
    ehd = (struct green_header_disk*)vmalloc(where.count << SECTOR_SHIFT);
    if (!ehd) {
		DMERR("check_header: Unable to allocate memory");
        return -ENOMEM;
    }

    r = dm_io_sync_vm(1, &where, READ, ehd, &bits, gc);
    if (r < 0) {
        DMERR("check_header: dm_io failed when reading metadata");
        goto exit_check;
    }

    header_from_disk(&header, ehd);
    if (header.magic != gc->header.magic 
            || header.version != gc->header.version
            || header.ndisk != gc->header.ndisk
            || header.ext_size != gc->header.ext_size
            || header.capacity != gc->header.capacity) {
        DMERR("check_header: Metadata header dismatch");
        r = -EINVAL;
        goto exit_check;
    }

exit_check:
    vfree(ehd);
    return r;
}

static int alloc_table(struct green_c *gc, bool zero)
{
    size_t size = vdisk_size(gc) * sizeof(struct vextent);

    gc->table = (struct vextent*)vmalloc(size);
    if (!(gc->table)) {
        DMERR("alloc_table: Unable to allocate memory");
        return -ENOMEM;
    }
    if (zero) {
        memset(gc->table, 0, size);
    }
    DMDEBUG("alloc_table: table created");

    return 0;
}

/*
 * Load metadata, which is saved in each disk right after extents data. 
 * Metadata format: <header> [<eid> <state> <counter>]+
 */
static int load_metadata(struct green_c *gc)
{
    int r;
    unsigned i;
    struct vextent_disk *extents;

    r = alloc_table(gc, false);
    if (r < 0)
        return r;

    extents = (struct vextent_disk*)vmalloc(table_size(gc));
    if (!extents) {
        DMERR("load_metadata: Unable to allocate memory");
        r = -ENOMEM;
        goto bad_extents;
    }

    /* Load table from 1st disk, which is considered as prime disk */
    r = sync_table(gc, extents, 0, READ);
    if (r < 0) 
        goto bad_sync;

    for (i = 0; i < vdisk_size(gc); ++i) { 
        extent_from_disk(gc->table + i, extents + i);
        if (gc->table[i].state & VES_PRESENT) { 
            DMDEBUG("mapping: %d -> %llu", i, gc->table[i].eid);
        }
    }

    vfree(extents);
    return 0;

bad_sync:
    vfree(extents);
bad_extents:
    vfree(gc->table);
    gc->table = NULL;
    return r;
}

static int build_bitmap(struct green_c *gc, bool zero)
{
    extent_t i; 
    unsigned j, k, size = bitmap_size(vdisk_size(gc));
    
    gc->bitmap = (unsigned long *)vmalloc(size);
    if (!gc->bitmap) {
        DMERR("build_bitmap: Unable to allocate memory");
        return -ENOMEM;
    }

    memset(gc->bitmap, 0, size);
    if (zero) {
        for (j = 0; j < fdisk_nr(gc); ++j)
            gc->disks[j].free_nr = gc->disks[j].capacity;
    } else {
        i = 0;
        for (j = 0; j < fdisk_nr(gc); ++j) {
            gc->disks[j].free_nr = gc->disks[j].capacity;
            for (k = 0; k < gc->disks[j].capacity; ++k) {
                if (gc->table[i].state & VES_PRESENT) {
#ifdef OLD_KERNEL
		    *gc->bitmap = *gc->bitmap | (unsigned long)(1<<i); 
#else
                    bitmap_set(gc->bitmap, i, 1);
#endif
                    gc->disks[j].free_nr--;
                    DMDEBUG("extent %llu is present", i);
                }
                ++i;
            }
        }
        BUG_ON(i != vdisk_size(gc));
        /*
        j = 0;
        k = gc->disks[j].capacity;
        gc->disks[j].free_nr = k;
        for (i = 0; i < vdisk_size(gc); ++i) {
            if (k == 0) { 
                DMDEBUG("free extent on disk %lu: %llu", 
                        j, gc->disks[j].free_nr);
                k = gc->disks[++j].capacity;
                gc->disks[j].free_nr = k;
            }
            if (gc->table[i].state & VES_PRESENT) {
                bitmap_set(gc->bitmap, i, 1);
                gc->disks[j].free_nr--;
                DMDEBUG("extent %d is present", i);
            }
            --k;
        }
        */
    }

    for (j = 0; j < fdisk_nr(gc); ++j) {
        DMDEBUG("free extent on disk %d: %llu", j, gc->disks[j].free_nr);
    }

    return 0;
}

static void clear_table(struct green_c *gc)
{
    unsigned i;

    for (i = 0; i < vdisk_size(gc); ++i) 
        gc->table[i].state &= ~VES_ACCESS;
}

/*
 * Map virtual extent 'veid' to physcial extent 'eid'.
 */
static void map_extent(struct green_c *gc, extent_t veid, extent_t eid)
{
    gc->table[veid].eid = eid;
    gc->table[veid].state |= VES_PRESENT;
    if (on_prime(gc, eid)) {
        gc->prime_extents[eid].vext = gc->table + veid;
    }
}

/*
 * Map bio's request onto physcial extent eid.
 */
static void map_bio(struct green_c *gc, struct bio *bio, extent_t eid)
{
    unsigned idisk;
    sector_t offset;          /* sector offset within extent */

    offset = (bio->bi_sector & (extent_size(gc) - 1));
    extent_on_disk(gc, &eid, &idisk);
    bio->bi_bdev = gc->disks[idisk].dev->bdev;
    bio->bi_sector = (eid << gc->ext_shift) + offset;
    /* Limit IO within an extent as it is fine to get less than wanted. */
    bio->bi_size = min(bio->bi_size, (unsigned int)to_bytes(extent_size(gc) - offset));
}

struct promote_info {
    struct green_c *gc;
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
        spin_lock(&(pinfo->gc->lock));
        put_prime(pinfo->gc, pinfo->peid);
        spin_unlock(&(pinfo->gc->lock));
    } else { 
        /* update new mapping */
        DMDEBUG("promote: extent %llu is remapped to extent %llu", 
                pinfo->veid, pinfo->peid);
        spin_lock(&(pinfo->gc->lock));
        put_extent(pinfo->gc, pinfo->gc->table[pinfo->veid].eid);
        pinfo->gc->table[pinfo->veid].eid = pinfo->peid;
        spin_unlock(&(pinfo->gc->lock));
        /* resubmit bio */
        map_bio(pinfo->gc, pinfo->bio, pinfo->peid);
		generic_make_request(pinfo->bio);
    }

    kfree(pinfo);
}

/*
 * Promote virtual extent 'veid'. This function returns immediately, but it
 * might schedule delayed operation and callback. Upon any failure, it
 * simply gives up. 
 */
static bool promote_extent(struct green_c *gc, struct bio *bio)
{
    struct dm_io_region src, dst;
    extent_t veid, peid, eid;
    unsigned idisk;
    struct promote_info *pinfo;

    DMDEBUG("promote_extent: promoting");
    if (get_prime(gc, &peid) < 0) { 
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

    veid = ((bio->bi_sector) >> gc->ext_shift);
    eid = gc->table[veid].eid;
    extent_on_disk(gc, &eid, &idisk);
    src.bdev = gc->disks[idisk].dev->bdev;
    src.sector = eid << gc->ext_shift;
    src.count = extent_size(gc);

    dst.bdev = gc->disks[PRIME_DISK].dev->bdev;
    dst.sector = peid << gc->ext_shift;
    dst.count = extent_size(gc);

    pinfo->gc = gc;
    pinfo->bio = bio;
    pinfo->veid = veid;
    pinfo->peid = peid;

    dm_kcopyd_copy(gc->kcp_client, &src, 1, &dst, 0, 
            (dm_kcopyd_notify_fn)promote_callback, pinfo);

    return true;
}

struct demote_info {
    struct green_c *gc;
    struct extent   *pext;      /* physical extent to demote */
    extent_t        seid;       /* source physical extent id */
    extent_t        deid;       /* dest physical extent id */
};

/*
 * Callback when an extent being demoted has been copied to other disk. 
 */
static void demote_callback(int read_err, unsigned long write_err, 
        void *context)
{
    struct demote_info *dinfo = (struct demote_info *)context;
    struct green_c *gc;
    struct extent *ext;
    struct extent *next, *prev;
    extent_t seid, deid;
    bool run_low = false;

    gc = dinfo->gc;
    ext = dinfo->pext;
    seid = dinfo->seid;
    deid = dinfo->deid;

    next = next_extent(&gc->prime_use, ext);
    prev = prev_extent(&gc->prime_use, ext);
    DMDEBUG("demote_callback: ext %llu -> %llu, next (%llu), prev (%llu)",
            seid, deid, ext2id(gc, next), ext2id(gc, prev));

    spin_lock(&gc->lock);
    ext->vext->state ^= VES_MIGRATE;
    if (read_err || write_err || (ext->vext->state & VES_ACCESS)) {
        /* undo demotion in case of error or extent is accessed */
		if (read_err)
			DMERR("demote_callback: Read error.");
		else if (write_err)
			DMERR("demote_callback: Write error.");
        else
            DMDEBUG("demote_callback: cancel demotion because of access");
        put_extent(gc, deid);
    } else {
        DMDEBUG("demote_callback: extent %u is remapped to extent %llu", 
                (ext->vext - gc->table), deid);
        ext->vext->state ^= VES_MIGRATE;
        ext->vext->eid = deid;
        put_extent(gc, seid);
        run_low = (prime_free_nr(gc) < EXTENT_FREE);
    }
    gc->demotion_running = false;
    spin_unlock(&gc->lock);
    kfree(dinfo);

    /* schedule more eviction */
//    if (run_low) 
//        queue_work(kgreend_wq, &gc->demotion_work);
}

/*
 * Return a least-recently-used extent on prime disk, NULL if not exist.
 */
static struct extent *lru_extent(struct green_c *gc)
{
    struct extent *ext, *next;

    if (gc->eviction_cursor == NULL) { 
        if (list_empty(&gc->prime_use)) { 
            DMDEBUG("lru_extent: Empty list");
            return NULL;
        }
        gc->eviction_cursor = list_first_entry(&gc->prime_use, 
                struct extent, list);
    }
    ext = gc->eviction_cursor;
    while (ext->vext->state & (VES_ACCESS | VES_MIGRATE)) { 
        DMDEBUG("lru_extent: Extent %llu accessed", ext2id(gc, ext));
        ext->vext->state ^= VES_ACCESS;     /* clear access bit */
        ext = next_extent(&gc->prime_use, ext);
        if (ext == gc->eviction_cursor) {   /* end of iteration */ 
            DMDEBUG("lru_extent: No eviction candidate");
            return NULL;
        }
    }
    next = next_extent(&gc->prime_use, ext);    /* advance lru cursor */
    gc->eviction_cursor = (next == ext) ? NULL : next;
    return ext;
}

/*
 * Demote extents using WSClock-LRU algorithm.
 */
static void demote_extent(struct green_c *gc)
{
    struct dm_io_region src, dst;
    struct extent *ext;
    extent_t seid, deid, tmp;
    unsigned idisk;
    struct demote_info *dinfo;

    dinfo = kmalloc(sizeof(struct demote_info), GFP_KERNEL);
    if (!dinfo) {
        DMDEBUG("demote_extent: Could not allocate memory");
        return ;
    }

    DMDEBUG("demote_extent: Demoting");
    spin_lock(&gc->lock);
    ext = lru_extent(gc);
    if (ext == NULL) { 
        DMDEBUG("demote_extent: Nothing to demote");
        goto quit_demote;
    }
    seid = ext2id(gc, ext);
    DMDEBUG("demote_extent: LRU extent is %llu", seid);

    if (get_extent(gc, &deid, false) < 0) { /* no space on disk */
        DMDEBUG("demote_extent: No space on disk");
        goto quit_demote;
    }
    ext->vext->state |= VES_MIGRATE;
    gc->demotion_running = true;
    spin_unlock(&gc->lock);

    BUG_ON(seid != ext->vext->eid || !on_prime(gc, seid) || on_prime(gc, deid));
    dinfo->gc = gc;
    dinfo->pext = ext;
    dinfo->seid = seid;
    dinfo->deid = deid;
    DMDEBUG("demote_extent: Demoting extent %llu from %llu to %llu", 
            vext2id(gc, ext->vext), seid, deid);

    src.bdev = gc->disks[PRIME_DISK].dev->bdev;
    src.sector = seid << gc->ext_shift;
    src.count = extent_size(gc);

    tmp = deid;
    extent_on_disk(gc, &tmp, &idisk);
    dst.bdev = gc->disks[idisk].dev->bdev;
    dst.sector = tmp << gc->ext_shift;
    dst.count = extent_size(gc);

    dm_kcopyd_copy(gc->kcp_client, &src, 1, &dst, 0,
            (dm_kcopyd_notify_fn)demote_callback, dinfo);
    return ;

quit_demote:
    spin_unlock(&gc->lock);
    kfree(dinfo);
}

static void demotion_work(struct work_struct *work)
{
    struct green_c *gc;

    gc = container_of(work, struct green_c, demotion_work);
    demote_extent(gc);
}

/*
 * Build LRU list and free list of extents on prime disk.
 */
static int build_prime(struct green_c *gc)
{
    size_t size; 
    extent_t eid, veid;

    size = sizeof(struct extent) * prime_size(gc);
    gc->prime_extents = (struct extent *)vmalloc(size);
    if (!gc->prime_extents) {
        DMERR("build_prime: Unable to allocate memory");
        return -ENOMEM;
    }
    memset(gc->prime_extents, 0, size);

    INIT_LIST_HEAD(&gc->prime_free);
    for (eid = 0; eid < prime_size(gc); ++eid) {
        list_add_tail(&(gc->prime_extents[eid].list), &gc->prime_free);
    }

    INIT_LIST_HEAD(&gc->prime_use);
    for (veid = 0; veid < vdisk_size(gc); ++veid) {
        if (!(gc->table[veid].state & VES_PRESENT))
            continue;
        eid = gc->table[veid].eid;
        if (on_prime(gc, eid)) { 
            gc->prime_extents[eid].vext = gc->table + veid;
            list_del(&(gc->prime_extents[eid].list));
            list_add_tail(&(gc->prime_extents[eid].list), &gc->prime_use);
            DMDEBUG("build_prime: prime extent %llu is in use", eid);
        }
    }

    return 0;
}

/*
 * Construct an green mapping.
 *  <extent size> <number of disks> [<dev> <number-of-extent>]+
 */
static int green_ctr(struct dm_target *ti, unsigned int argc, char **argv)
{
    uint32_t ndisk;
    uint32_t ext_size;
	char *end;
    struct green_c *gc;
    int r;

    DMDEBUG("green_ctr (argc: %d)", argc);

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

    gc = alloc_context(ti, ndisk, ext_size);
    if (!gc) {
        ti->error = "Fail to allocate memory for green context";
        return -ENOMEM;
    }
    DMDEBUG("extent size: %u;  extent shift: %u", ext_size, gc->ext_shift);

    r = get_disks(gc, argv+2);
    if (r < 0) {
        ti->error = "Fail to get mapped disks";
        goto bad_disks;
    }

#ifdef OLD_KERNEL
    gc->io_client = dm_io_client_create(0); /* "0" needs verification */
#else
    gc->io_client = dm_io_client_create();
#endif

    if (IS_ERR(gc->io_client)) {
		r = PTR_ERR(gc->io_client);
        ti->error = "Fail to create dm_io_client";
        goto bad_io_client;
    }

#ifdef OLD_KERNEL
    dm_kcopyd_client_create((unsigned int)0, (struct dm_kcopyd_client **)&gc->kcp_client); /* "0" and "NULL" need verification */
#else
    gc->kcp_client = dm_kcopyd_client_create();
#endif
    if (IS_ERR(gc->kcp_client)) {
		r = PTR_ERR(gc->io_client);
        ti->error = "Fail to create dm_io_client";
        goto bad_kcp_client;
    }

    r = check_header(gc, 0);
    if (r < 0) {
        DMDEBUG("no useable metadata on disk");
        r = alloc_table(gc, true);
        if (r < 0) {
            ti->error = "Fail to alloc table";
            goto bad_metadata;
        }
        r = build_bitmap(gc, true);
        if (r < 0) {
            ti->error = "Fail to build bitmap";
            goto bad_bitmap;
        }
    } else {
        DMDEBUG("loading metadata from disk");
        r = load_metadata(gc);
        if (r < 0) {
            ti->error = "Fail to load metadata";
            goto bad_metadata;
        }
        r = build_bitmap(gc, false);
        if (r < 0) {
            ti->error = "Fail to build bitmap";
            goto bad_bitmap;
        }
    }

    r = build_prime(gc);
    if (r < 0) {
        DMDEBUG("building prime extents");
        ti->error = "Fail to build prime extents";
        goto bad_prime;
    }

    clear_table(gc);
    INIT_WORK(&gc->demotion_work, demotion_work);
    gc->demotion_running = false;

    return 0;

bad_prime:
    vfree(gc->bitmap);
    gc->bitmap = NULL;
bad_bitmap:
    vfree(gc->table);
    gc->table = NULL;
bad_metadata:
    dm_kcopyd_client_destroy(gc->kcp_client);
bad_kcp_client:
    dm_io_client_destroy(gc->io_client);
bad_io_client:
    put_disks(gc, ndisk);
bad_disks:
    free_context(gc);

    return r;
}

static void green_dtr(struct dm_target *ti)
{
    struct green_c *gc = (struct green_c*)ti->private;

    DMDEBUG("green_dtr");
    flush_workqueue(kgreend_wq);
    if (dump_metadata(gc) < 0) 
        DMERR("Fail to dump metadata");

    dm_kcopyd_client_destroy(gc->kcp_client);
    dm_io_client_destroy(gc->io_client);
    put_disks(gc, fdisk_nr(gc));
    free_context(gc);
}

static int green_map(struct dm_target *ti, struct bio *bio,
        union map_info *map_context)
{
    struct green_c *gc = (struct green_c*)ti->private;
    extent_t eid, veid = ((bio->bi_sector) >> gc->ext_shift);
    bool run_demotion = false;

    DMDEBUG("%lu: map(sector %llu -> extent %llu)", jiffies, 
            bio->bi_sector, veid);
    spin_lock(&gc->lock);
    gc->table[veid].state |= VES_ACCESS;
    gc->table[veid].tick = jiffies_64;
    gc->table[veid].counter++;
    if (gc->table[veid].state & VES_PRESENT) {
        eid = gc->table[veid].eid;
        DMDEBUG("map: virtual %llu -> physical %llu", veid, eid);
        if (!on_prime(gc, eid)) {
            if ((bio->bi_rw & 1) == READ) {
                /* Try to promote extent on read. No matter the promotion
                 * succeed or not, map the io */
                /* promote_extent(gc, bio)) */
            } else if ((bio->bi_rw & 1) == WRITE) {
                /* exam if mapped extent is under promotion, map io if yes,
                 * otherwise wait until the promotion is done. */
            }
        } 
    } else {
        BUG_ON(get_extent(gc, &eid, true) < 0);   /* out of space */
        map_extent(gc, veid, eid);
    }
    run_demotion = (prime_free_nr(gc) < EXTENT_LOW) && !gc->demotion_running;
    spin_unlock(&gc->lock);

    map_bio(gc, bio, eid);

    if (run_demotion) {              /* schedule extent eviction */
        queue_work(kgreend_wq, &gc->demotion_work);
    }

    return DM_MAPIO_REMAPPED;
}

static int green_status(struct dm_target *ti, status_type_t type,
        char *result, unsigned int maxlen)
{
    unsigned i;
    extent_t free = 0;
    struct green_c *gc = (struct green_c *)ti->private;

    DMDEBUG("green_status");
    switch(type) {
        case STATUSTYPE_INFO:
            result[0] = '\0';
            break;

        case STATUSTYPE_TABLE:
            for (i = 0; i < fdisk_nr(gc); ++i) 
                free += gc->disks[i].free_nr;
            snprintf(result, maxlen, "extent size: %u, capacity: %llu \
                    free prime extents: %llu, free extents: %llu",
                    extent_size(gc), vdisk_size(gc), 
                    gc->disks[PRIME_DISK].free_nr, free);
            break;
    }
    return 0;
}

static struct target_type green_target = {
	.name	     = "green",
	.version     = {0, 1, 0},
	.module      = THIS_MODULE,
	.ctr	     = green_ctr,
	.dtr	     = green_dtr,
	.map	     = green_map,
	.status	     = green_status,
};

static int __init green_init(void)
{
    int r = 0;

    kgreend_wq = create_workqueue(GREEN_DAEMON);
    if (!kgreend_wq) {
        DMERR("Couldn't start " GREEN_DAEMON);
        goto bad_workqueue;
    }

	r = dm_register_target(&green_target);
    if (r < 0) {
        DMERR("green register failed %d\n", r);
        goto bad_register;
    }

    DMDEBUG("green initialized");
    return r;

bad_register:
    destroy_workqueue(kgreend_wq);
bad_workqueue:
    return r;
}

static void __exit green_exit(void)
{
	dm_unregister_target(&green_target);
    destroy_workqueue(kgreend_wq);
}

module_init(green_init);
module_exit(green_exit);

MODULE_DESCRIPTION(DM_NAME " green target");
MODULE_AUTHOR("Ming Chen <mchen@cs.stonybrook.edu>");
MODULE_LICENSE("GPL");
