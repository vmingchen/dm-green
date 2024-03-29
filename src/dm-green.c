/*
 * Copyright (C) 2012   Ming Chen, Rajesh Aavuty
 * Copyright (C) 2012	Zhichao Li
 * Copyright (C) 2012   Erez Zadok
 * Copyright (c) 2012   Stony Brook University
 * Copyright (c) 2012   The Research Foundation of SUNY
 * 
 * One green target by cache implementation to make OS components green by 
 * data grouping that redirects reads/writes to mapped physical disks for 
 * energy and performance benefits. 
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#include "dm-green.h"

static struct workqueue_struct *kgreend_wq;
static struct dentry * file; 
static int disk_spin_pid; 
static struct task_struct * user_prog = NULL; 

/* Set a single bit of bitmap */
static inline void green_bm_set(unsigned long *bitmap, int pos) 
{
#ifdef OLD_KERNEL
    unsigned long *p;

    p = bitmap + pos / BITS_PER_LONG;
    *p |= (unsigned long)(1 << (BITS_PER_LONG - 1 - (pos % BITS_PER_LONG)));
#else
    bitmap_set(bitmap, pos, 1);
#endif
}

/* Clear a single bit of bitmap */
static inline void green_bm_clear(unsigned long *bitmap, int pos)
{
#ifdef OLD_KERNEL
    unsigned long *p;

    p = bitmap + pos / BITS_PER_LONG;
    *p &= (unsigned long)(~(1 << (BITS_PER_LONG - 1 - (pos % BITS_PER_LONG))));
#else
    bitmap_clear(bitmap, pos, 1);
#endif
}

/* Check a single bit of bitmap: set or not */
static inline unsigned long green_bm_check(unsigned long *bitmap, int pos)
{
    unsigned long *p;

    p = bitmap + pos / BITS_PER_LONG;
    return *p & (unsigned long)(1 << (BITS_PER_LONG - 1 - (pos % BITS_PER_LONG)));
}

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

	/* gc->bitmap is not initialized here */
    spin_lock_init(&gc->lock);

    gc->table = NULL;           /* table not allocated yet */
    gc->io_client = NULL;
    gc->kcp_client = NULL;
    gc->cache_extents = NULL;

    return gc;
}

static void free_context(struct green_c *gc)
{
    VERIFY(gc && (gc->disks));

    if (gc->table) {
        vfree(gc->table);
        gc->table = NULL;
    }
    if (gc->bitmap) {
        vfree(gc->bitmap);
        gc->bitmap = NULL;
    }
    if (gc->cache_extents) {
        vfree(gc->cache_extents);
        gc->cache_extents = NULL;
    }

    kfree(gc->disks);
    kfree(gc);
}

static inline void header_to_disk(struct green_header *core, 
        struct green_header_disk *disk)
{   
	/* always store into little endian format */
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

/* Get a mapped disk and check if it is sufficiently large */
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
	if(idisk == CACHE_DISK) {
		/* bd_inode (inode of bdev) field will die. It relies on kernel version. */
		dev_size = gc->disks[idisk].dev->bdev->bd_inode->i_size >> SECTOR_SHIFT;
		if (dev_size < len + header_size() + table_size(gc) + bitmap_size(vdisk_size(gc))) 
			return -ENOSPC;
	}
	else {
		/* bd_inode (inode of bdev) field will die. It relies on kernel version. */
		dev_size = gc->disks[idisk].dev->bdev->bd_inode->i_size >> SECTOR_SHIFT;
		if (dev_size < len)
			return -ENOSPC;

	}

    return 0;
}

/* Put disk devices */
static void put_disks(struct green_c *gc, int ndisk)
{
    int i;

    for (i = 0; i < ndisk; ++i) {
        dm_put_device(gc->ti, gc->disks[i].dev);
    }
}

/* Get all disk devices and check if disk size matches */
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
        GREEN_ERROR("Disk length dismatch");
        r = -EINVAL;
    }

    gc->eviction_cursor = gc->disks[CACHE_DISK].capacity - 1;

    return r;
}

/* Check if physical extent 'ext' is on cache disk */
static inline bool on_cache(struct green_c *gc, extent_t eid)
{
    return eid < cache_size(gc);
}

/* Return physical extent id from extent pointer */
static inline extent_t ext2id(struct green_c *gc, struct extent *ext)
{
	/* array offset */
    return (ext - gc->cache_extents);
}

/* 
 * Return virtual extent id from vextent pointer, vext is got from
 * gc->cache_extents[xx].vext
 */
static inline extent_t vext2id(struct green_c *gc, struct vextent *vext)
{
    return (vext - gc->table);
}

/*
 * Return physical disk id and offset of physical extent. Note, parameters
 * passed in as pointers will be changed in this function. Otherwise,
 * it will cause sectors mismatch. 
 *
 * 'eid': [IN/OUT] extent id before/after the virtual to physical translation.
 * 'idisk': [OUT] physical disk id.
 */
static inline void extent_on_disk(struct green_c *gc, extent_t *eid,
        unsigned *idisk)
{
    VERIFY(*eid < vdisk_size(gc));
    *idisk = 0;
    while (*idisk < fdisk_nr(gc) && *eid >= gc->disks[*idisk].capacity) {
        *eid -= gc->disks[(*idisk)++].capacity;
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

/* Return the previous extent in a *non-empty* list */
static inline struct extent *prev_extent(struct list_head *head,
        struct extent *ext)
{
    return (ext->list.prev != head)
        ? list_entry(ext->list.prev, struct extent, list)
        : list_entry(head->prev, struct extent, list);
}

/* Get a cache extent */
static inline int get_from_cache(struct green_c *gc, extent_t *eid)
{
    struct extent *first;

    if (list_empty(&gc->cache_free)) 
        return -ENOSPC;

    first = list_first_entry(&(gc->cache_free), struct extent, list);
    list_del(&first->list);
    list_add_tail(&first->list, &gc->cache_use);
    *eid = ext2id(gc, first);

    gc->disks[CACHE_DISK].free_nr--;

    green_bm_set(gc->bitmap, *eid);

    GREEN_ERROR("Get %llu (%llu extents left)", 
            *eid, gc->disks[CACHE_DISK].free_nr);

    return 0;
}

/* Free a cache extent */
static inline void put_cache(struct green_c *gc, extent_t eid)
{
    struct extent *ext;

    VERIFY(eid < cache_size(gc));
    ext = gc->cache_extents + eid;
    ext->vext = NULL;
    list_del(&ext->list);
    list_add(&ext->list, &(gc->cache_free));
    gc->disks[CACHE_DISK].free_nr++;

    green_bm_clear(gc->bitmap, eid);

    GREEN_ERROR("%llu cache extents left", gc->disks[CACHE_DISK].free_nr);
}

/* Get a physical extent */
static int get_extent(struct green_c *gc, extent_t *eid, bool cache)
{
    unsigned i;

	/* Look for free spot from Cache first, if cache is set */
    if (cache && get_from_cache(gc, eid) == 0) 
        return 0;

    for (i = CACHE_DISK+1; i < fdisk_nr(gc); ++i) {
        if (gc->disks[i].free_nr > 0) {
            *eid = find_next_zero_bit(gc->bitmap, vdisk_size(gc), 
                    gc->disks[i].offset);
            GREEN_ERROR("%llu obtained", *eid);
            gc->disks[i].free_nr--;
            green_bm_set(gc->bitmap, *eid);
            return 0;
        }
    }

    return -ENOSPC;
}

#if 0
/* Free a physcial extent */
static void put_extent(struct green_c *gc, extent_t eid)
{
    unsigned i;

    VERIFY(eid < vdisk_size(gc));
    for (i = 0; eid >= gc->disks[i].capacity + gc->disks[i].offset; ++i)
        ;

	/* if free extent from Cache */
    if (i == CACHE_DISK) {   
        put_cache(gc, eid);
    } else { 
        gc->disks[i].free_nr++;
        green_bm_clear(gc->bitmap, eid);
    }
}
#endif

/* 
 * Wrapper function for new dm_io API 
 *
 * NOTE: It makes a difference between sync and async IO. 
 */
static int dm_io_sync_vm(unsigned num_regions, struct dm_io_region *where,
        int rw, void *data, unsigned long *error_bits, struct green_c *gc)
{
    struct dm_io_request iorq;

    iorq.bi_rw= rw;
    iorq.mem.type = DM_IO_VMA;
    iorq.mem.ptr.vma = data;

	/* set notify.fn to be async IO. NULL means sync IO */
    iorq.notify.fn = NULL;
    iorq.client = gc->io_client;

    return dm_io(&iorq, num_regions, where, error_bits);
}

static inline void locate_header(struct dm_io_region *where, 
        struct green_c *gc, unsigned idisk)
{
	/* dm_io_region coupled with dm_io_memory  */
    where->bdev = gc->disks[idisk].dev->bdev;	
    where->sector = gc->disks[idisk].capacity << gc->ext_shift; /* starting sector */
    where->count = header_size(); 				/* how many sectors the header needs */
    VERIFY(where->count <= MAX_SECTORS);
}

/* Dump metadata header to a disk */
static int dump_header(struct green_c *gc, unsigned idisk)
{
    int r = 0;
    unsigned long bits;
    struct green_header_disk *header;
    struct dm_io_region where;

    locate_header(&where, gc, idisk);
    header = (struct green_header_disk*)vmalloc(where.count << SECTOR_SHIFT);
    if (!header) {
        GREEN_ERROR("Unable to allocate memory");
        return -ENOMEM;
    }

    header_to_disk(&(gc->header), header);
    r = dm_io_sync_vm(1, &where, WRITE, header, &bits, gc);
    if (r < 0) {
        GREEN_ERROR("Fail to write metadata header");
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
            GREEN_ERROR("Unable to sync table");
            vfree(extents);
            return r;
        }
        data += (where.count << SECTOR_SHIFT);
    }

    return 0;
}

static int sync_bitmap(struct green_c *gc, unsigned long * bitmap, 
        unsigned idisk, int rw)
{
    int r;
    unsigned long bits;
    struct dm_io_region where;
    sector_t index, offset, size = count_sector(bitmap_size(vdisk_size(gc)));
    void *data = (void*)bitmap;

    where.bdev = gc->disks[idisk].dev->bdev;
    offset = (gc->disks[idisk].capacity << gc->ext_shift) + header_size() + table_size(gc); 
    for (index = 0; index < size; index += where.count) {
        where.sector = offset + index;
        where.count = (size - index) < MAX_SECTORS 
            ? (size - index) : MAX_SECTORS;
        r = dm_io_sync_vm(1, &where, rw, data, &bits, gc); 
        if (r < 0) {
            GREEN_ERROR("Unable to sync bitmap");
            vfree(bitmap);
            return r;
        }
        data += (where.count << SECTOR_SHIFT);
    }

    return 0;
}

/*
 * Dump metadata to SSD. 
 *
 * For performance boost, all metadata should be dumped to most
 * efficient device (SSD), especially under the condition that the
 * flush exhibits the periodic feature. 
 *
 */
static int dump_metadata(struct green_c *gc)
{
    int r;
    extent_t veid;
    struct vextent_disk *extents;
	unsigned long *bitmap; 

    extents = (struct vextent_disk *)vmalloc(table_size(gc) * SECTOR_SIZE);
    if (!extents) {
        GREEN_ERROR("Unable to allocate memory");
        return -ENOMEM;
    }

    for (veid = 0; veid < vdisk_size(gc); ++veid) { 
        extent_to_disk(gc->table + veid, extents + veid);
        if (gc->table[veid].state & VES_PRESENT) { 
            GREEN_ERROR("%llu -> %llu (%llu)", veid, 
                    le64_to_cpu(extents[veid].eid), gc->table[veid].eid);
        }
    }

	bitmap = (unsigned long *)vmalloc(bitmap_size(vdisk_size(gc))); 
	if(!bitmap) {
		GREEN_ERROR("Unable to allocate memory"); 
        vfree(extents);
		return -ENOMEM; 
	}

	/* TODO: endian issue for bitmap */
	memcpy(bitmap, gc->bitmap, bitmap_size(vdisk_size(gc))); 

	/* only flush metadata to SSD */
#if 0
    for (i = 0; i < fdisk_nr(gc); ++i) {
#endif
        r = dump_header(gc, CACHE_DISK);
        if (r < 0) {
            GREEN_ERROR("Fail to dump header to disk %u", CACHE_DISK);
			goto free; 
        }
        r = sync_table(gc, extents, CACHE_DISK, WRITE);
        if (r < 0) {
            GREEN_ERROR("Fail to dump mapping table to disk %u", CACHE_DISK);
			goto free; 
        }
        r = sync_bitmap(gc, bitmap, CACHE_DISK, WRITE);
        if (r < 0) {
            GREEN_ERROR("Fail to dump bitmap to disk %u", CACHE_DISK);
			goto free; 
        }
#if 0
    }
#endif

free: 
    vfree(extents);
	vfree(bitmap); 
    return r;
}

/* Check metadata header from a disk */
static int check_header(struct green_c *gc, unsigned idisk)
{
    int r = 0;
    unsigned long bits;
    struct green_header_disk *ehd;
    struct green_header header;
    struct dm_io_region where;

    locate_header(&where, gc, idisk);

	/* simple one: vmalloc(sizeof(struct green_header_disk) */
    ehd = (struct green_header_disk*)vmalloc(where.count << SECTOR_SHIFT);
    if (!ehd) {
		GREEN_ERROR("Unable to allocate memory");
        return -ENOMEM;
    }

	/* synchronous IO, check Documentation/device-mapper/dm-io.txt */
    r = dm_io_sync_vm(1, &where, READ, ehd, &bits, gc);
    if (r < 0) {
        GREEN_ERROR("dm_io failed when reading metadata");
        goto exit_check;
    }

    header_from_disk(&header, ehd);
    if (header.magic != gc->header.magic 
            || header.version != gc->header.version
            || header.ndisk != gc->header.ndisk
            || header.ext_size != gc->header.ext_size
            || header.capacity != gc->header.capacity) {
        GREEN_ERROR("Metadata header dismatch");
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
        GREEN_ERROR("Unable to allocate memory");
        return -ENOMEM;
    }
    if (zero) {
		/* zero out means no state for every reachable virtual extent */
        memset(gc->table, 0, size);
    }
    GREEN_ERROR("Table created");

    return 0;
}

static int alloc_bitmap(struct green_c *gc, bool zero)
{
    gc->bitmap = (unsigned long *)vmalloc(bitmap_size(vdisk_size(gc)));
    if (!(gc->bitmap)) {
        GREEN_ERROR("Unable to allocate memory");
        return -ENOMEM;
    }
    if (zero) {
		/* zero out means no state for every reachable virtual extent */
        memset(gc->bitmap, 0, bitmap_size(vdisk_size(gc)));
    }
    GREEN_ERROR("Bitmap created");

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

    extents = (struct vextent_disk*)vmalloc(table_size(gc) * SECTOR_SIZE);
    if (!extents) {
        GREEN_ERROR("Unable to allocate memory");
        r = -ENOMEM;
        goto bad_extents;
    }

    /* Load table from 1st disk, which is considered as cache disk */
    r = sync_table(gc, extents, 0, READ);
    if (r < 0) 
        goto bad_sync;

    for (i = 0; i < vdisk_size(gc); ++i) { 
        extent_from_disk(gc->table + i, extents + i);
        if (gc->table[i].state & VES_PRESENT) { 
            GREEN_ERROR("Mapping %d -> %llu", i, gc->table[i].eid);
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

/* load bitmap information from SSD */
static int load_bitmap(struct green_c *gc)
{
    int r;
	extent_t i; 
	unsigned j,k; 
	unsigned long *bitmap; 

	r = alloc_bitmap(gc, false); 
	if(r < 0) 
		return r; 

    bitmap = (unsigned long *)vmalloc(bitmap_size(vdisk_size(gc)));
    if (!bitmap) {
        GREEN_ERROR("Unable to allocate memory");
        r = -ENOMEM;
        goto bad_bitmap;
    }

    /* Load table from 1st disk, which is considered as cache disk */
    r = sync_bitmap(gc, bitmap, 0, READ);
    if (r < 0) 
        goto bad_sync;

	/* TODO: endian issue for bitmap */
	memcpy(gc->bitmap, bitmap, bitmap_size(vdisk_size(gc))); 

	i = 0;
	for (j = 0; j < fdisk_nr(gc); ++j) {
		gc->disks[j].free_nr = gc->disks[j].capacity;
		for (k = 0; k < gc->disks[j].capacity; ++k) {
			if (green_bm_check(gc->bitmap, i)) {
				gc->disks[j].free_nr--;
				GREEN_ERROR("Extent %llu is set in bitmap", i);
			}
			++i;
		}
	}
	VERIFY(i == vdisk_size(gc));

    vfree(bitmap);
    return 0;

bad_sync:
    vfree(bitmap);
bad_bitmap:
	vfree(gc->bitmap); 
	gc->bitmap = NULL; 
    return r;
}

static int build_bitmap(struct green_c *gc, bool zero)
{
    unsigned j, size = bitmap_size(vdisk_size(gc));
    
    gc->bitmap = (unsigned long *)vmalloc(size);
    if (!gc->bitmap) {
        GREEN_ERROR("Unable to allocate memory");
        return -ENOMEM;
    }

    memset(gc->bitmap, 0, size);
    if (zero) {
        for (j = 0; j < fdisk_nr(gc); ++j)
            gc->disks[j].free_nr = gc->disks[j].capacity;
    } 

    for (j = 0; j < fdisk_nr(gc); ++j) {
        GREEN_ERROR("Free extent on disk %d: %llu", j, gc->disks[j].free_nr);
    }

    return 0;
}

static void clear_table(struct green_c *gc)
{
    unsigned i;

    for (i = 0; i < vdisk_size(gc); ++i) 
        gc->table[i].state &= ~VES_ACCESS;
}

/* Get virtual extent id of bio offset  */
static inline extent_t get_bio_offset(struct green_c *gc, struct bio *bio)
{
	return (bio->bi_sector - gc->ti->begin) >> gc->ext_shift;
}

/* Map virtual extent 'veid' to physcial extent 'eid' */
static void map_extent(struct green_c *gc, extent_t veid, extent_t eid)
{
    gc->table[veid].eid = eid;
    gc->table[veid].state |= VES_PRESENT;

	/* If the physical extent is mapped to Cache */
    if (on_cache(gc, eid)) {
		/* map from Cache extent to virtual extent */
        gc->cache_extents[eid].vext = gc->table + veid;
    }
}

/* Update bio's request onto physcial extent eid */
static void map_bio(struct green_c *gc, struct bio *bio, extent_t eid)
{
    unsigned idisk;
    struct dm_target *ti = gc->ti;
    sector_t offset;          /* sector offset within extent */

    /* Get offset within extent. */
    offset = ((bio->bi_sector - ti->begin) & (extent_size(gc) - 1));

    extent_on_disk(gc, &eid, &idisk);
    bio->bi_bdev = gc->disks[idisk].dev->bdev;
    bio->bi_sector = ti->begin + (eid << gc->ext_shift) + offset;

    /* Limit IO within an extent as it is fine to get less than wanted. */
    bio->bi_size = min(bio->bi_size, 
            (unsigned int)to_bytes(extent_size(gc) - offset));
}

#if 0
/* Callback when an extent being evictd has been copied to other disk */
static void evict_callback(int read_err, unsigned long write_err, 
        void *context)
{
    struct evict_info *dinfo = (struct evict_info *)context;
    struct green_c *gc;
    struct extent *ext;
    struct extent *next, *prev;
    extent_t seid, deid;
	unsigned long flags; 

    gc = dinfo->gc;
    ext = dinfo->pext;
    seid = dinfo->seid;
    deid = dinfo->deid;

    next = next_extent(&gc->cache_use, ext);
    prev = prev_extent(&gc->cache_use, ext);
    GREEN_ERROR("ext %llu -> %llu, next (%llu), prev (%llu)",
            seid, deid, ext2id(gc, next), ext2id(gc, prev));

    spin_lock_irqsave(&gc->lock, flags);
    ext->vext->state &= ~VES_MIGRATE;

    if (read_err || write_err || (ext->vext->state & VES_ACCESS)) {
        /* undo eviction in case of error or extent is accessed */
		if (read_err)
			GREEN_ERROR("Read error.");
		else if (write_err)
			GREEN_ERROR("Write error.");
        else
            GREEN_ERROR("Cancel eviction because of access");
        put_extent(gc, deid);
    } 
    else {
        GREEN_ERROR("Extent %u is remapped to extent %llu", 
                (unsigned int)(ext->vext - gc->table), deid);
		/* update mapping table for dest physical extent */
        ext->vext->eid = deid;
        put_extent(gc, seid);
    }
#if 0
    gc->eviction_running = false;
#endif
    spin_unlock_irqrestore(&gc->lock, flags);
    kfree(dinfo);
}
#endif

/*
 * Return a least-recently-used physical extent on cache disk, NULL if not exist.
 *
 * NOTE: This is in fact a WSClock cache replacement algorithm, not an 
 * exact LRU algorithm. 
 *
 * One example LRU algorithm can be using counter for each cached
 * chunk(extent), everytime one chunk is accessed, the counter for the
 * accessed chunk is set to 0, all the other counters are increased by
 * 1. The process keeps running until the cache is full, when the
 * chunk with the largest counter will be replaced. 
 * 
 * Time complexity: O(n) (more complex than WSClock algorithm)
 * Space complexity: O(n) (half the space of WSClock algorithm)
 */
static struct extent *lru_extent(struct green_c *gc)
{
    struct extent *ext;
    extent_t i;

    i = gc->eviction_cursor;    /* start from last position */
    do {
        /* advance cursor, wrap if the end is reached */
        if (++i >= gc->disks[CACHE_DISK].capacity) 
            i = 0;
        GREEN_ERROR("Cursor at %llu", i);

        ext = gc->cache_extents + i;
        if (ext->vext == NULL) 
            continue;       /* skip free extent */

        if (ext->vext->state & (VES_ACCESS | VES_MIGRATE)) {
            GREEN_ERROR("Extent %llu accessed or migrating", ext2id(gc, ext));
            ext->vext->state &= ~VES_ACCESS;        /* clear access bit */
        } else {
            gc->eviction_cursor = i;
            return ext;
        }
#if 0
    } while (i != gc->eviction_cursor);
#endif
    } while (true);

    VERIFY(false);
    GREEN_ERROR("It is a bug");
    return NULL;
}

#if 0
/* Evict extents using WSClock algorithm */
static extent_t evict_extent(struct green_c *gc)
{
    struct dm_io_region src, dst;
    struct extent *ext;
    extent_t seid, deid, tmp;
    unsigned idisk;
    struct evict_info *dinfo;
    unsigned long flags;
    int r;

    dinfo = kmalloc(sizeof(struct evict_info), GFP_KERNEL);
    if (!dinfo) {
        GREEN_ERROR("Could not allocate memory");
        return (extent_t)(-1);
    }

    GREEN_ERROR("Eviction");
    spin_lock_irqsave(&gc->lock, flags);
    ext = lru_extent(gc);
    spin_unlock_irqrestore(&gc->lock, flags);

    if (ext == NULL) { 
        GREEN_ERROR("Nothing to evict");
        goto quit_evict;
    }
    seid = ext2id(gc, ext);
    GREEN_ERROR("LRU extent is %llu", seid);

	/* Get one free extent as the dest place */
    spin_lock_irqsave(&gc->lock, flags);
    r = get_extent(gc, &deid, false);
    spin_unlock_irqrestore(&gc->lock, flags);
    if (r < 0) { /* no space on disk */
        GREEN_ERROR("No space on non-cache disk");
        goto quit_evict;
    }
	/* TODO: spin up disk */
    ext->vext->state |= VES_MIGRATE;
#if 0
    gc->eviction_running = true;
#endif

    VERIFY(seid == ext->vext->eid && on_cache(gc, seid) && !on_cache(gc, deid));
    dinfo->gc = gc;
    dinfo->pext = ext;
    dinfo->seid = seid;
    dinfo->deid = deid;
    GREEN_ERROR("Evict extent %llu from %llu to %llu", 
            vext2id(gc, ext->vext), seid, deid);

    src.bdev = gc->disks[CACHE_DISK].dev->bdev;
    src.sector = seid << gc->ext_shift;
    src.count = extent_size(gc);

    tmp = deid;
    extent_on_disk(gc, &tmp, &idisk);
    dst.bdev = gc->disks[idisk].dev->bdev;
    dst.sector = tmp << gc->ext_shift;
    dst.count = extent_size(gc);

    dm_kcopyd_copy(gc->kcp_client, &src, 1, &dst, 0,
            (dm_kcopyd_notify_fn)evict_callback, dinfo);
	/* TODO: spin down to save power */
    return seid;

quit_evict:
    kfree(dinfo);
	return (extent_t)(-1); 
}
#endif

/*
 * Callback of promote_extent. It should release resources allocated by
 * promote_extent properly upon either success or failure.
 *
 * Moreover, this a pending IO request of this promotion. It should be issued 
 * no matter the promotion succeeds or fails.
 */
#if 0
static void promote_callback(int read_err, unsigned long write_err,
        void *context)
{
    struct promote_info *pinfo = (struct promote_info *)context;
    struct green_c *gc = pinfo->gc;
    extent_t eid;
	unsigned long flags; 

    if (read_err || write_err) {
		if (read_err)
			GREEN_ERROR("Read error.");
		else
			GREEN_ERROR("Write error.");
        /* undo promote */
        spin_lock_irqsave(&(gc->lock), flags);
        put_cache(gc, pinfo->peid);
        eid = gc->table[pinfo->veid].eid;          /* the old physical extent */
        gc->table[pinfo->veid].state ^= VES_PROMOTE;
        spin_unlock_irqrestore(&(gc->lock), flags);
    } else { 
        /* update mapping table */
        GREEN_ERROR("Extent %llu is remapped to extent %llu", 
                pinfo->veid, pinfo->peid);
        spin_lock_irqsave(&(gc->lock), flags);
        put_extent(gc, gc->table[pinfo->veid].eid); 			/* release old extent */
        eid = gc->table[pinfo->veid].eid = pinfo->peid; 		/* the new extent */
		gc->cache_extents[eid].vext = gc->table + pinfo->veid;  /* cache management */
        gc->table[pinfo->veid].state ^= VES_PROMOTE;
        gc->table[pinfo->veid].state |= VES_ACCESS; 			/* newly promoted extent accessed */
        spin_unlock_irqrestore(&(gc->lock), flags);
    }
    /* resubmit bio */
    map_bio(gc, pinfo->bio, eid);
    generic_make_request(pinfo->bio);

    kfree(pinfo);
}
#endif 

/*
 * Promote virtual extent 'veid'. This function returns immediately, but it
 * might schedule delayed operation and callback. Upon any failure, it
 * simply gives up. 
 *
 */
#if 0
static void promote_extent(struct green_c *gc, struct bio *bio)
{
    struct dm_io_region src, dst;
    extent_t veid, peid = 0, eid;
    unsigned idisk;
    struct promote_info *pinfo;
    unsigned long flags;
    int r;

    GREEN_ERROR("Promoting");
    pinfo = (struct promote_info *)kmalloc(
            sizeof(struct promote_info), GFP_KERNEL);
    if (!pinfo) {
        GREEN_ERROR("Could not allocate memory");
        return;        /* out of memory */
    }

    spin_lock_irqsave(&gc->lock, flags);
    r = get_from_cache(gc, &peid);
    spin_unlock_irqrestore(&gc->lock, flags);

    if (r < 0) { 
        GREEN_ERROR("No extent on cache disk");
		/* If cache is full, do cache replacement */
		peid = evict_extent(gc); 
		if(peid < 0) {
			GREEN_ERROR("Evict_extent error"); 
            kfree(pinfo);
			return; 
		}
    }

	/* TODO: spin up disk */

	/* build source place */
    veid = ((bio->bi_sector) >> gc->ext_shift);
    gc->table[veid].state |= VES_PROMOTE;
    eid = gc->table[veid].eid;
    extent_on_disk(gc, &eid, &idisk);
    src.bdev = gc->disks[idisk].dev->bdev;
    src.sector = eid << gc->ext_shift;
    src.count = extent_size(gc);

	/* build cache place */
    dst.bdev = gc->disks[CACHE_DISK].dev->bdev;
    dst.sector = peid << gc->ext_shift;
    dst.count = extent_size(gc);

	/* build context */
    pinfo->gc = gc;
    pinfo->bio = bio;
    pinfo->veid = veid;
    pinfo->peid = peid;

	/* pinfo is the context passed to the callback routine */
    dm_kcopyd_copy(gc->kcp_client, &src, 1, &dst, 0, 
            (dm_kcopyd_notify_fn)promote_callback, pinfo);

	/* TODO: spin down disk */

    return;
}
#endif

static struct dm_io_region locate_extent(struct green_c *gc, extent_t eid)
{
    unsigned idisk;
    struct dm_io_region where;

    extent_on_disk(gc, &eid, &idisk);
    where.bdev = gc->disks[idisk].dev->bdev;
    where.sector = (eid << gc->ext_shift);
    where.count = extent_size(gc);

    return where;
}

/*
 * Swap two disk extents using memory as temporal storage. 
 * TODO: use kmem_cache for memory allocation
 */
static int swap_extent(struct green_c *gc, extent_t eid1, extent_t eid2) 
{
    void *mext1, *mext2;
    struct dm_io_region region1, region2;
    unsigned long bits;
    int r;

    GREEN_DEBUG("Swapping %lld and %lld", eid1, eid2);

	/* vmalloc while holds spin lock; change to kmalloc(size, GFP_ATOMIC) */
    mext1 = vmalloc(extent_size(gc) << SECTOR_SHIFT);
    if (!mext1) {
        GREEN_ERROR("Unable to allocate memory");
        return -ENOMEM;
    }

    mext2 = vmalloc(extent_size(gc) << SECTOR_SHIFT);
    if (!mext2) {
        GREEN_ERROR("Unable to allocate memory");
        vfree(mext1);
        return -ENOMEM;
    }

    /* load extent eid1 to mext1 */
    GREEN_DEBUG("Loading extent %lld", eid1);
    region1 = locate_extent(gc, eid1);
    r = dm_io_sync_vm(1, &region1, READ, mext1, &bits, gc);
    if (r < 0) {
        GREEN_ERROR("Unable to load extent %lld", eid1);
        goto exit_swap;
    }

    /* load extent eid2 to mext2 */
    GREEN_DEBUG("Loading extent %lld", eid2);
    region2 = locate_extent(gc, eid2);
    r = dm_io_sync_vm(1, &region2, READ, mext2, &bits, gc);
    if (r < 0) {
        GREEN_ERROR("Unable to load extent %lld", eid2);
        goto exit_swap;
    }

    /* write mext1 to extent eid2 */
    GREEN_DEBUG("Writing %lld to %lld", eid1, eid2);
    r = dm_io_sync_vm(1, &region2, WRITE, mext1, &bits, gc);
    if (r < 0) {
        GREEN_ERROR("Unable to write extent %lld", eid2);
        goto exit_swap;
    }

    /* write mext2 to extent eid1 */
    GREEN_DEBUG("Writing %lld to %lld", eid2, eid1);
    r = dm_io_sync_vm(1, &region1, WRITE, mext2, &bits, gc);
    if (r < 0) {
        GREEN_ERROR("Unable to write extent %lld", eid1);
        goto exit_swap;
    }

exit_swap:
    vfree(mext2);
    vfree(mext1);
    return r;
}

/*
 * Swap two extent mappings in the mapping table.
 * veid_c: virtual extent id that is mapped onto the cache disk
 * veid_s: virtual extent id that is mapped onto one secondary disk
 */
static void swap_entry(struct green_c *gc, extent_t veid_c, extent_t veid_s)
{
    extent_t eid_c; /* physical extent id on the cache disk */
    extent_t eid_s; /* physical extent id on the secondary disk */

    eid_c = gc->table[veid_c].eid;
    eid_s = gc->table[veid_s].eid;
    map_extent(gc, veid_s, eid_c);
    map_extent(gc, veid_c, eid_s);
}

/* 
 * Undertake migration work. It returns 0 on success, <0 on failure. 
 */
static int migrate_extent(struct green_c *gc, struct migration_info *minfo)
{
    extent_t veid_c, eid_c, veid_s, eid_s;
    struct extent *ext;
    unsigned long flags;
    int r;

    veid_s = minfo->veid_s;
    eid_s = minfo->eid_s;

    GREEN_ERROR("Migrating extent (v%lld, %lld)", veid_s, eid_s);

	/* Grab a cache extent (LRU) and setup migration states */
    spin_lock_irqsave(&gc->lock, flags);
    /* get extent to be evicted */
    ext = lru_extent(gc);
    veid_c = minfo->veid_c = vext2id(gc, ext->vext);
    eid_c = minfo->eid_c = ext->vext->eid;
	VERIFY(on_cache(gc, eid_c)&&(!on_cache(gc, eid_s))); 
    /* set states */
    gc->table[veid_s].state |= VES_MIGRATE;
    gc->table[veid_c].state |= VES_MIGRATE;
    spin_unlock_irqrestore(&gc->lock, flags);

    r = swap_extent(gc, eid_c, eid_s);

    spin_lock_irqsave(&gc->lock, flags);
    if (r < 0) {
        /* Fail to replace extent on cache disk, roll back */
        GREEN_ERROR("Cannot swap %lld and %lld", eid_c, eid_s);
    } else {
        /* Update mapping table */
        GREEN_ERROR("%lld and %lld swapped", eid_c, eid_s);
        swap_entry(gc, veid_c, veid_s);
    }
    gc->table[veid_c].state &= ~VES_MIGRATE;
    gc->table[veid_s].state &= ~VES_MIGRATE;
    spin_unlock_irqrestore(&gc->lock, flags);

    return r;
}

/* Extract a migration_info from queue; put it into migration_list. */
static struct migration_info *dequeue_migration(struct green_c *gc)
{
    struct migration_info *minfo;

    VERIFY(!list_empty(&gc->migration_queue));
    minfo = list_first_entry(&gc->migration_queue, struct migration_info, list);
    list_del(&minfo->list);
    list_add(&minfo->list, &gc->migration_list);
    return minfo;
}

/* Process a migration job. */
static void migration_work(struct work_struct *work)
{
    struct green_c *gc;
    struct migration_info *minfo;
    unsigned long flags;
    struct bio *bio;
    extent_t veid;
    int r;

    GREEN_ERROR("Migration work called");
    gc = container_of(work, struct green_c, migration_work);

    spin_lock_irqsave(&gc->lock, flags);
    minfo = dequeue_migration(gc);
    spin_unlock_irqrestore(&gc->lock, flags);

    r = migrate_extent(gc, minfo);

    /* no matter migration succeed or not, submit all bios. */
    while (!bio_list_empty(&minfo->pending_bios)) {
        bio = bio_list_pop(&minfo->pending_bios);
        bio->bi_next = NULL;       /* it is a single bio instead of a bio_list */
        veid = get_bio_offset(gc, bio);
        /*
         * How bio is mapped depends on two factors: 1) the extent it is pending
         * on; 2) the migration succeeds or not.
         * 1. pending on the extent on secondary disk (which is being promoted)
         *      a. migration succeeds: mapped to eid_c
         *      b. migration fails: mapped to eid_s
         * 2. pending on the extent on cache disk (which is being demoted)
         *      a. migration succeeds: mapped to eid_s
         *      b. migration fails: mapped to eid_c
         */
        if (veid == minfo->veid_s) { 
            GREEN_ERROR("Bio %lld submitted to %lld", bio->bi_sector, 
                    r == 0 ? minfo->eid_c : minfo->eid_s);
            map_bio(gc, bio, r == 0 ? minfo->eid_c : minfo->eid_s);
        } else { 
            GREEN_ERROR("Bio %lld submitted to %lld", bio->bi_sector, 
                    r == 0 ? minfo->eid_s : minfo->eid_c);
            map_bio(gc, bio, r == 0 ? minfo->eid_s : minfo->eid_c);
        }
        generic_make_request(bio);
    }

    /* delete from migration list */
    list_del(&minfo->list);

    kfree(minfo);
}

/* Submit a migration work by add a migration_info into queue */
static bool queue_migration(struct green_c *gc, struct bio *bio, 
        extent_t veid, extent_t eid)
{
    struct migration_info *minfo;

    minfo = kmalloc(sizeof(struct migration_info), GFP_ATOMIC);
    if (!minfo) {
        GREEN_ERROR("Cannot allocate memory");
        return false;
    }

    /* setup migration_info */
    minfo->veid_s = veid;
    minfo->eid_s = eid;
    minfo->veid_c = -1;     /* uninitialized yet */
    bio_list_init(&minfo->pending_bios);
    bio_list_add(&minfo->pending_bios, bio);

    list_add_tail(&minfo->list, &gc->migration_queue);
    queue_work(kgreend_wq, &gc->migration_work);

    GREEN_ERROR("Migration of extent %lld queued", eid);

    return true;
}

/* Insert a bio into a list of migration_info */
static bool insert_bio(struct list_head *mlist, struct bio *bio, extent_t veid)
{
    struct migration_info *minfo;

    list_for_each_entry(minfo, mlist, list) {
        GREEN_ERROR("minfo->veid_c: %lld; minfo->veid_s: %lld", 
                minfo->veid_s, minfo->veid_c);
        if (minfo->veid_s == veid || minfo->veid_c == veid) {
            bio_list_add(&minfo->pending_bios, bio);
            GREEN_ERROR("bio with offset %lld inserted", bio->bi_sector);
            return true;
        }
    }
    return false;
}

/* Pend a bio for an extent which is under migration. */
static void pend_bio(struct green_c *gc, struct bio *bio, extent_t veid)
{
    GREEN_ERROR("Trying to pend bio %lld with veid %lld", 
            bio->bi_sector, veid);

    if (!insert_bio(&gc->migration_list, bio, veid) 
            && !insert_bio(&gc->migration_queue, bio, veid)) {
        GREEN_ERROR("Cannot find pending extent %lld", veid);
    }
}

/* Build free and used lists of extents on cache disk */
static int build_cache(struct green_c *gc)
{
    size_t size; 
    extent_t eid, veid;

    size = sizeof(struct extent) * cache_size(gc);
    gc->cache_extents = (struct extent *)vmalloc(size);
    if (!gc->cache_extents) {
        GREEN_ERROR("Unable to allocate memory");
        return -ENOMEM;
    }
    memset(gc->cache_extents, 0, size);

    INIT_LIST_HEAD(&gc->cache_free);
    for (eid = 0; eid < cache_size(gc); ++eid) {
		/* free list of struct extent */
        list_add_tail(&(gc->cache_extents[eid].list), &gc->cache_free);
    }

	/* initially, use list empty; after redirecting, list rearrange */
    INIT_LIST_HEAD(&gc->cache_use);
    for (veid = 0; veid < vdisk_size(gc); ++veid) {
        if (!(gc->table[veid].state & VES_PRESENT))
            continue;
		/* If mapping exists */
        eid = gc->table[veid].eid;
        if (on_cache(gc, eid)) { 
            gc->cache_extents[eid].vext = gc->table + veid;
            list_del(&(gc->cache_extents[eid].list));
            list_add_tail(&(gc->cache_extents[eid].list), &gc->cache_use);
            GREEN_ERROR("Cache extent %llu is in use", eid);
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

    GREEN_ERROR("argc is %d", argc);

    if (argc < 4) {
        ti->error = "Not enough arguments";
        return -EINVAL;
    }

    ext_size = simple_strtoul(argv[0], &end, 10);
    if (*end || !is_power_of_2(ext_size) 
            || (ext_size < (PAGE_SIZE >> SECTOR_SHIFT))) {
		/*
		 * NOTE: the extent size does not necessarily to be less than
		 * one page. IO should be sector based. 
		 */
        ti->error = "Invalid extent size";
		return -EINVAL;
    }

    if (ti->len & (ext_size - 1)) {
        ti->error = "Target length not divisible by extent size";
        return -EINVAL;
    }

    ndisk = simple_strtoul(argv[1], &end, 10);
    if ((ndisk<1) || *end) {
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
    GREEN_ERROR("Extent size: %u;  extent shift: %u", ext_size, gc->ext_shift);

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
    /* "0" needs verification */
    dm_kcopyd_client_create((unsigned int)0, 
            (struct dm_kcopyd_client **)&gc->kcp_client); 
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
        GREEN_ERROR("No useable metadata on disk");

        /* 
         * This happens when it is the first time the disk is used. 
		 * However, the current manner of processing is too simple. 
		 *
		 * We should add some special mechnism to do this initialization, 
		 * because it might destory the old data already in the disks.     
		 *
		 * If we are assuming that when creating the virtual device, 
		 * the multi disks are ready to be formatted, we just need 
		 * to write the metadata as we like. 
		 *
		 * If not, we just need to first migrate the metadata from the
		 * multi-disk to other persistent storage for snapshot purpose. 
         */

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
        GREEN_ERROR("Loading metadata from disk");
        r = load_metadata(gc);
        if (r < 0) {
            ti->error = "Fail to load metadata";
            goto bad_metadata;
        }
        r = load_bitmap(gc);
        if (r < 0) {
            ti->error = "Fail to build bitmap";
            goto bad_bitmap;
        }
    }

	/* First use or use after loaded from disk */
    r = build_cache(gc);
    if (r < 0) {
        GREEN_ERROR("Building cache extents");
        ti->error = "Fail to build cache extents";
        goto bad_cache;
    }

    clear_table(gc);
	/* map kernel thread id to thread work function */

    INIT_WORK(&gc->migration_work, migration_work);
    INIT_LIST_HEAD(&gc->migration_queue);
    INIT_LIST_HEAD(&gc->migration_list);
#if 0
    gc->eviction_running = false;
#endif

    /* prevent io from acrossing extent */
    ti->split_io = ext_size;
    ti->num_flush_requests = ndisk;
#ifndef OLD_KERNEL
    ti->num_discard_requests = ndisk;
#endif

	/* TODO: 
	 * spin down disks when the green context is created for
	 * power benefit. 
	 */

    return 0;

/* free memory reversely */
bad_cache:
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

    GREEN_ERROR("green_dtr");
    flush_workqueue(kgreend_wq);
    if (dump_metadata(gc) < 0) 
        GREEN_ERROR("Fail to dump metadata");

    dm_kcopyd_client_destroy(gc->kcp_client);
    dm_io_client_destroy(gc->io_client);
    put_disks(gc, fdisk_nr(gc));
    free_context(gc);
}

static int green_map(struct dm_target *ti, struct bio *bio,
        union map_info *map_context)
{
    struct green_c *gc = (struct green_c*)ti->private;
	unsigned long flags; 

	/* bio->bi_sector is based on virtual sector specified in argv */
    extent_t eid = 0; 
	extent_t veid = get_bio_offset(gc, bio);

#if 0
    bool run_eviction = false;
#endif

#ifndef OLD_KERNEL
	unsigned target_request_nr;

    if (bio->bi_rw & REQ_FLUSH) {
        target_request_nr = map_context->target_request_nr;
        VERIFY(target_request_nr < fdisk_nr(gc));
        bio->bi_bdev = gc->disks[target_request_nr].dev->bdev;
        return DM_MAPIO_REMAPPED;
    }
#endif

    GREEN_ERROR("%lu: map(sector %llu -> extent %llu)", jiffies, 
            (long long unsigned int)(bio->bi_sector - ti->begin), veid);

    spin_lock_irqsave(&gc->lock, flags);
    gc->table[veid].state |= VES_ACCESS;
#if 0
    gc->table[veid].tick = jiffies_64;
#endif
    gc->table[veid].tick = get_jiffies_64();
    gc->table[veid].counter++;

	/* if the mapping table is setup already */
    if (gc->table[veid].state & VES_PRESENT) {
        if (gc->table[veid].state & VES_MIGRATE) {
            pend_bio(gc, bio, veid);
            spin_unlock_irqrestore(&gc->lock, flags);
            GREEN_ERROR("Extent %lld is under migration", veid);
            return DM_MAPIO_SUBMITTED;
        }
        eid = gc->table[veid].eid;
    } else {
     /* If the mapping is not present yet, get one free physical extent */
        VERIFY(get_extent(gc, &eid, true) >= 0);   /* out of space */
        map_extent(gc, veid, eid);
    }

    GREEN_ERROR("virtual %llu -> physical %llu", veid, eid);
    /* cache miss */
    if (!on_cache(gc, eid) && queue_migration(gc, bio, veid, eid)) {

        /* 
        eid = migrate_extent(gc, veid, eid);

        promote_extent(gc, bio); 
        */
        spin_unlock_irqrestore(&gc->lock, flags);
        return DM_MAPIO_SUBMITTED;
    }/* end of cache miss */ 
    /* If cache hits, then performance benefits from Design */
    else {
        /* In the beginning: cache extent state is already set to be accessed */
    }
    spin_unlock_irqrestore(&gc->lock, flags);

#if 0
    run_eviction = (cache_free_nr(gc) < EXT_MIN_THRESHOLD) 
            && !gc->eviction_running;
#endif

    map_bio(gc, bio, eid);
    generic_make_request(bio);

#if 0
    if (run_eviction) {              /* schedule extent eviction */
		/* remember to flush_work */
        queue_work(kgreend_wq, &gc->eviction_work);
    }
#endif

    return DM_MAPIO_SUBMITTED;
}

static int green_status(struct dm_target *ti, status_type_t type,
        char *result, unsigned int maxlen)
{
    unsigned i;
    extent_t free = 0;
    struct green_c *gc = (struct green_c *)ti->private;

    switch(type) {
        case STATUSTYPE_INFO:
        GREEN_ERROR("green info");
            result[0] = '\0';
            break;

        case STATUSTYPE_TABLE:
        GREEN_ERROR("green table");
            for (i = 0; i < fdisk_nr(gc); ++i) 
                free += gc->disks[i].free_nr;
            snprintf(result, maxlen, "extent size: %u, capacity: %llu \
                    free cache extents: %llu, free extents: %llu",
                    extent_size(gc), vdisk_size(gc), 
                    gc->disks[CACHE_DISK].free_nr, free);
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
	/* .message is not used for now */
};

/* 
 * send signal to spin down specific device.
 *
 * @dev is the last char of devices (e.g., 'b', 'c', 'd' stands 
 * 	    for /dev/sdb, /dev/sdc, /dev/sdd, etc)
 */
static void wrap_disk_spin_down(const char dev) {
    int ret;
    struct siginfo info;

    /* send the signal */
    memset(&info, 0, sizeof(struct siginfo));
    info.si_signo = SIG_TEST;
    info.si_code = SI_QUEUE;    
    info.si_int = 1234 + dev - 'a';    	   /* real time signals may have 32 bits of data */

	VERIFY(user_prog != NULL); 
    ret = send_sig_info(SIG_TEST, &info, user_prog);  				  /* send the signal */
    if (ret < 0) {
        GREEN_ERROR("error sending signal\n");
        return; 
    }
}

/* get the user level program pid for disk spin down */
static ssize_t write_pid(struct file *f, const char __user *buf, 
					size_t count, loff_t *ppos) 
{
    char pid_buf[10];
	struct pid * pid; 

    if(count > 10)
        return -EINVAL;

    /* read the value from user space */
    if (copy_from_user(pid_buf, buf, count)) 
        return -EFAULT;

    sscanf(pid_buf, "%d", &disk_spin_pid);
    printk("user_disk_spin pid = %d\n", disk_spin_pid);

    rcu_read_lock();
	/* NOTE: get_pid_task is exported from Linux 3.0 */
	pid = find_get_pid(disk_spin_pid); 
    user_prog = get_pid_task(pid, PIDTYPE_PID);   /* find the task_struct associated */
    if(user_prog == NULL){
        GREEN_ERROR("no such pid\n");
        rcu_read_unlock();
        return -ENODEV;
    }
    rcu_read_unlock();

    return count;
}

/* file operations used by debugfs */
static const struct file_operations my_fops = {
	.write 		 = write_pid, 
}; 

static int __init green_init(void)
{
    int r = 0;

	/* work queue scheduling kernel threads */
    kgreend_wq = create_workqueue(GREEN_DAEMON);
    if (!kgreend_wq) {
        GREEN_ERROR("Couldn't start " GREEN_DAEMON);
        goto bad_workqueue;
    }

	/* create one debugfs entry (write only) */
	file = debugfs_create_file("signal_greendm", 0222, NULL, NULL, &my_fops); 
	if(file == NULL) {
		GREEN_ERROR("create debugfs entry failed\n"); 
		goto bad_debugfs_entry; 	
	}

	/* register the green target */
    r = dm_register_target(&green_target);
    if (r < 0) {
        GREEN_ERROR("Green register failed %d\n", r);
        goto bad_register;
    }

    GREEN_ERROR("Green initialized");
    return r;
	
bad_register: 
	debugfs_remove(file); 
bad_debugfs_entry:
    destroy_workqueue(kgreend_wq);
bad_workqueue:
    return r;
}

static void __exit green_exit(void)
{
    dm_unregister_target(&green_target);
	debugfs_remove(file); 
    destroy_workqueue(kgreend_wq);
}

module_init(green_init);
module_exit(green_exit);

MODULE_DESCRIPTION(DM_NAME " A green multi-disk target");
MODULE_LICENSE("GPL");
