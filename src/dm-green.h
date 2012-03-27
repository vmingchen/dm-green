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

#ifndef _DM_GREEN_H
#define _DM_GREEN_H

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

#define DM_MSG_PREFIX "green"

/* Define this macro if compile before Linux 3.0 */
#define OLD_KERNEL

/* Magic for persistent green header */
#define GREEN_MAGIC 0x45614567
#define GREEN_VERSION 53
#define GREEN_DAEMON "kgreend"

/* The first disk is cache disk. */
#define CACHE_DISK 0

/* SECTOR_SHIFT is defined in device-mapper.h as 9 */
#define SECTOR_SIZE (1 << SECTOR_SHIFT)

/* Given size x, how many sectors it contains */
#define count_sector(x) (((x) + SECTOR_SIZE - 1) >> SECTOR_SHIFT)

/* Return metadata's size in unit of sector */
#define header_size() \
    count_sector(sizeof(struct green_header_disk))

#define table_size(gc) \
    count_sector(gc->header.capacity * sizeof(struct vextent_disk))

/* Return size of bitmap array in unit of unsigned long; round up to the ceiling */
#define bitmap_size(sz) dm_round_up(sz, sizeof(unsigned long))

#define extent_size(gc) (gc->header.ext_size)
#define vdisk_size(gc) (gc->header.capacity)
#define cache_size(gc) (gc->disks[CACHE_DISK].capacity)
#define cache_free_nr(gc) (gc->disks[CACHE_DISK].free_nr)
#define fdisk_nr(gc) (gc->header.ndisk)

/* 
 * When requesting a new bio, the number of requested bvecs has to be
 * less than BIO_MAX_PAGES (defined in bio.h to be 256). 
 * Otherwise, null is returned. 
 *
 * In dm-io.c, this return value is not checked and kernel Oops may 
 * happen. We set the limit here to avoid such situations. (2 additional 
 * bvecs are required by dm-io for bookeeping.) (From dm-cache)
 *
 * PAGE_SIZE is defined in asm/linux-generic/page.h to be 4KB (1<<12)
 */
#define MAX_SECTORS ((BIO_MAX_PAGES - 2) * (PAGE_SIZE >> SECTOR_SHIFT))

/* When free extents are less than EXTENT_LOW, demotion is triggered */
#define EXTENT_LOW 4

/* The total number of free extents on the cache disk after demotion */
#define EXTENT_FREE_NUM 8

/* 
 * Borrowed from dm_array_too_big, defined in device-mapper.h 
 * UNIT_MAX is ~0U, defined in linux/kernel.h
 */
#define array_too_big(fixed, obj, num) \
	((num) > (UINT_MAX - (fixed)) / (obj))

/* extent id type */
typedef uint64_t extent_t; 

/* Header in memory, contained in green context (green_c) */
struct green_header {
    uint32_t magic;
    uint32_t version;
    uint32_t ndisk;
    uint32_t ext_size;
    extent_t capacity;          /* capacity in extent */
};

/* Header on disk, followed by metadata of mapping table */
struct green_header_disk {
    __le32 magic;
    __le32 version;
    __le32 ndisk;
    __le32 ext_size;
    __le64 capacity;
} __packed;

/* Three bits represent three different virtual extent states */
#define VES_PRESENT 0x01
#define VES_ACCESS  0x02
#define VES_MIGRATE 0x04

/* Virtual extent in memory */
struct vextent {
    extent_t eid;               /* physical extent id */
    uint32_t state;             /* extent states and flags */
    uint32_t counter;           /* how many times are accessed */
    uint64_t tick;              /* timestamp of latest access */
};

/* Extent metadata on disk */
struct vextent_disk {
    __le64 eid;
    __le32 state;
    __le32 counter;
} __packed;

/* Memory structure for physical extent on cache disk */
struct extent {
    struct vextent *vext;       /* virtual extent */
    struct list_head list;
};

/* Ring buffer of physical free extent after demotion */
struct extent_buffer {
    extent_t data[EXTENT_FREE_NUM]; 	/* array of physical extent id */
    unsigned capacity;          
    unsigned cursor;            	/* cursor of first entent id */
    unsigned count;             	/* number of valid extents */
};

/* Memory structure to represent a physical disk */
struct mapped_disk {
    struct dm_dev *dev;
    extent_t capacity;          /* capacity in extent */
    extent_t free_nr;           /* number of free extents */
    extent_t offset;            /* offset within virtual disk in extent */
};

/* Context of green target, containing all the information of our disk */
struct green_c {
    struct dm_target *ti;

    struct green_header header;
    uint32_t flags;
    uint32_t ext_shift;

    struct mapped_disk *disks;      /* mapped disks, sequential storage */

    struct vextent *table;          /* mapping table, sequential storage */

    struct extent *cache_extents;   /* physical extents on cache disk, sequential storage */
    struct list_head cache_free;    /* free extents on cache disk */
    struct list_head cache_use;     /* in-use extents on cache disk */

    unsigned long *bitmap;      /* bitmap of extent, '0' for free extent */
    spinlock_t lock;            /* protect table, free and bitmap */

    struct dm_io_client *io_client;
    struct dm_kcopyd_client *kcp_client; /* data copy in device mapper */

    struct work_struct demotion_work;    /* work of evicting cache extent */
    struct extent *demotion_cursor;
    bool demotion_running; 
};

/* Information passed between promotion function and its callback */
struct promote_info {
    struct green_c *gc;
    struct bio      *bio;   /* bio to submit after migration */
    extent_t        veid;   /* virtual extent to promote */
    extent_t        peid;   /* destinate cache extent of the promotion */
};

/* Information passed between demotion function and its callback */
struct demote_info {
    struct green_c *gc;
    struct extent   *pext;      /* physical extent to demote */
    extent_t        seid;       /* source physical extent id */
    extent_t        deid;       /* dest physical extent id */
};

#endif
