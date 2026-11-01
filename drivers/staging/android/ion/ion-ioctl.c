/*
 *
 * Copyright (C) 2011 Google, Inc.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#include <linux/kernel.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/idr.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/dma-buf.h>
#include <linux/dma-direction.h>

#include "ion.h"
#include "ion_system_secure_heap.h"

union ion_ioctl_arg {
	struct ion_allocation_data allocation;
	struct ion_heap_query query;
	struct ion_prefetch_data prefetch_data;
};

static int validate_ioctl_arg(unsigned int cmd, union ion_ioctl_arg *arg)
{
	int ret = 0;

	switch (cmd) {
	case ION_IOC_HEAP_QUERY:
		ret = arg->query.reserved0 != 0;
		ret |= arg->query.reserved1 != 0;
		ret |= arg->query.reserved2 != 0;
		break;
	default:
		break;
	}

	return ret ? -EINVAL : 0;
}

/* fix up the cases where the ioctl direction bits are incorrect */
static unsigned int ion_ioctl_dir(unsigned int cmd)
{
	switch (cmd) {
	default:
		return _IOC_DIR(cmd);
	}
}


/*
 * Legacy (pre-4.12) ION UAPI emulation.
 *
 * The Android 9 vendor blobs (qseecomd, libQSEEComAPI, camera, video...) still talk to /dev/ion with the old
 * handle based ioctls. Handles are emulated on top of dma-bufs and kept per open file.
 */
struct ion_legacy_ctx {
	struct idr handles;
	struct mutex lock;
};

struct ion_legacy_alloc64 {
	__u64 len;
	__u64 align;
	__u32 heap_id_mask;
	__u32 flags;
	__s32 handle;
	__u32 pad;
};

struct ion_legacy_alloc32 {
	__u32 len;
	__u32 align;
	__u32 heap_id_mask;
	__u32 flags;
	__s32 handle;
};

struct ion_legacy_handle_data {
	__s32 handle;
};

struct ion_legacy_fd_data {
	__s32 handle;
	__s32 fd;
};

struct ion_legacy_custom64 {
	__u32 cmd;
	__u32 pad;
	__u64 arg;
};

struct ion_legacy_custom32 {
	__u32 cmd;
	__u32 arg;
};

struct ion_legacy_flush64 {
	__s32 handle;
	__s32 fd;
	__u64 vaddr;
	__u32 offset;
	__u32 length;
};

struct ion_legacy_flush32 {
	__s32 handle;
	__s32 fd;
	__u32 vaddr;
	__u32 offset;
	__u32 length;
};

#define ION_LEGACY_MAGIC		'I'
#define ION_LEGACY_IOC_ALLOC64		_IOWR(ION_LEGACY_MAGIC, 0, struct ion_legacy_alloc64)
#define ION_LEGACY_IOC_ALLOC32		_IOWR(ION_LEGACY_MAGIC, 0, struct ion_legacy_alloc32)
#define ION_LEGACY_IOC_FREE		_IOWR(ION_LEGACY_MAGIC, 1, struct ion_legacy_handle_data)
#define ION_LEGACY_IOC_MAP		_IOWR(ION_LEGACY_MAGIC, 2, struct ion_legacy_fd_data)
#define ION_LEGACY_IOC_SHARE		_IOWR(ION_LEGACY_MAGIC, 4, struct ion_legacy_fd_data)
#define ION_LEGACY_IOC_IMPORT		_IOWR(ION_LEGACY_MAGIC, 5, struct ion_legacy_fd_data)
#define ION_LEGACY_IOC_SYNC		_IOWR(ION_LEGACY_MAGIC, 7, struct ion_legacy_fd_data)
#define ION_LEGACY_IOC_CUSTOM64		_IOWR(ION_LEGACY_MAGIC, 6, struct ion_legacy_custom64)
#define ION_LEGACY_IOC_CUSTOM32		_IOWR(ION_LEGACY_MAGIC, 6, struct ion_legacy_custom32)

#define ION_LEGACY_MSM_MAGIC		'M'
#define ION_LEGACY_CLEAN_CACHES64	_IOWR(ION_LEGACY_MSM_MAGIC, 0, struct ion_legacy_flush64)
#define ION_LEGACY_INV_CACHES64		_IOWR(ION_LEGACY_MSM_MAGIC, 1, struct ion_legacy_flush64)
#define ION_LEGACY_CLEAN_INV_CACHES64	_IOWR(ION_LEGACY_MSM_MAGIC, 2, struct ion_legacy_flush64)
#define ION_LEGACY_CLEAN_CACHES32	_IOWR(ION_LEGACY_MSM_MAGIC, 0, struct ion_legacy_flush32)
#define ION_LEGACY_INV_CACHES32		_IOWR(ION_LEGACY_MSM_MAGIC, 1, struct ion_legacy_flush32)
#define ION_LEGACY_CLEAN_INV_CACHES32	_IOWR(ION_LEGACY_MSM_MAGIC, 2, struct ion_legacy_flush32)

int ion_legacy_open(struct inode *inode, struct file *filp)
{
	struct ion_legacy_ctx *ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);

	if (!ctx)
		return -ENOMEM;
	idr_init(&ctx->handles);
	mutex_init(&ctx->lock);
	filp->private_data = ctx;
	return 0;
}

static int ion_legacy_release_one(int id, void *ptr, void *data)
{
	dma_buf_put(ptr);
	return 0;
}

int ion_legacy_release(struct inode *inode, struct file *filp)
{
	struct ion_legacy_ctx *ctx = filp->private_data;

	if (!ctx)
		return 0;
	idr_for_each(&ctx->handles, ion_legacy_release_one, NULL);
	idr_destroy(&ctx->handles);
	kfree(ctx);
	filp->private_data = NULL;
	return 0;
}

static int ion_legacy_add(struct ion_legacy_ctx *ctx, struct dma_buf *buf)
{
	int id;

	mutex_lock(&ctx->lock);
	id = idr_alloc(&ctx->handles, buf, 1, 0, GFP_KERNEL);
	mutex_unlock(&ctx->lock);
	return id;
}

static struct dma_buf *ion_legacy_get(struct ion_legacy_ctx *ctx, int handle)
{
	struct dma_buf *buf;

	mutex_lock(&ctx->lock);
	buf = idr_find(&ctx->handles, handle);
	if (buf)
		get_dma_buf(buf);
	mutex_unlock(&ctx->lock);
	return buf;
}

static int ion_legacy_alloc(struct ion_legacy_ctx *ctx, size_t len,
			    unsigned int heap_id_mask, unsigned int flags)
{
	struct dma_buf *buf;
	int handle;

	buf = ion_alloc_dmabuf(len, heap_id_mask, flags);
	if (IS_ERR(buf))
		return PTR_ERR(buf);
	handle = ion_legacy_add(ctx, buf);
	if (handle < 0)
		dma_buf_put(buf);
	return handle;
}

static int ion_legacy_flush(struct ion_legacy_ctx *ctx, unsigned int op, int handle, int fd)
{
	struct dma_buf *buf;
	int ret = 0;

	buf = handle > 0 ? ion_legacy_get(ctx, handle) : dma_buf_get(fd);
	if (!buf || IS_ERR(buf))
		return -EINVAL;

	switch (op) {
	case 0:	/* clean */
		ret = dma_buf_end_cpu_access(buf, DMA_TO_DEVICE);
		break;
	case 1:	/* invalidate */
		ret = dma_buf_begin_cpu_access(buf, DMA_FROM_DEVICE);
		break;
	default: /* clean + invalidate */
		ret = dma_buf_begin_cpu_access(buf, DMA_BIDIRECTIONAL);
		if (!ret)
			ret = dma_buf_end_cpu_access(buf, DMA_BIDIRECTIONAL);
		break;
	}
	dma_buf_put(buf);
	return ret;
}

/* Returns -ENOIOCTLCMD when the command is not a legacy one. */
static long ion_legacy_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct ion_legacy_ctx *ctx = filp->private_data;
	void __user *uarg = (void __user *)arg;
	struct ion_legacy_fd_data fdd;
	struct dma_buf *buf;
	int ret;

	switch (cmd) {
	case ION_LEGACY_IOC_ALLOC64:
	{
		struct ion_legacy_alloc64 a;

		if (copy_from_user(&a, uarg, sizeof(a)))
			return -EFAULT;
		ret = ion_legacy_alloc(ctx, a.len, a.heap_id_mask, a.flags);
		if (ret < 0)
			return ret;
		a.handle = ret;
		return copy_to_user(uarg, &a, sizeof(a)) ? -EFAULT : 0;
	}
	case ION_LEGACY_IOC_ALLOC32:
	{
		struct ion_legacy_alloc32 a;

		if (copy_from_user(&a, uarg, sizeof(a)))
			return -EFAULT;
		ret = ion_legacy_alloc(ctx, a.len, a.heap_id_mask, a.flags);
		if (ret < 0)
			return ret;
		a.handle = ret;
		return copy_to_user(uarg, &a, sizeof(a)) ? -EFAULT : 0;
	}
	case ION_LEGACY_IOC_FREE:
	{
		struct ion_legacy_handle_data h;

		if (copy_from_user(&h, uarg, sizeof(h)))
			return -EFAULT;
		mutex_lock(&ctx->lock);
		buf = idr_remove(&ctx->handles, h.handle);
		mutex_unlock(&ctx->lock);
		if (!buf)
			return -EINVAL;
		dma_buf_put(buf);
		return 0;
	}
	case ION_LEGACY_IOC_MAP:
	case ION_LEGACY_IOC_SHARE:
		if (copy_from_user(&fdd, uarg, sizeof(fdd)))
			return -EFAULT;
		buf = ion_legacy_get(ctx, fdd.handle);
		if (!buf)
			return -EINVAL;
		ret = dma_buf_fd(buf, O_CLOEXEC);
		if (ret < 0) {
			dma_buf_put(buf);
			return ret;
		}
		fdd.fd = ret;
		return copy_to_user(uarg, &fdd, sizeof(fdd)) ? -EFAULT : 0;
	case ION_LEGACY_IOC_IMPORT:
		if (copy_from_user(&fdd, uarg, sizeof(fdd)))
			return -EFAULT;
		buf = dma_buf_get(fdd.fd);
		if (IS_ERR(buf))
			return PTR_ERR(buf);
		ret = ion_legacy_add(ctx, buf);
		if (ret < 0) {
			dma_buf_put(buf);
			return ret;
		}
		fdd.handle = ret;
		return copy_to_user(uarg, &fdd, sizeof(fdd)) ? -EFAULT : 0;
	case ION_LEGACY_IOC_SYNC:
		if (copy_from_user(&fdd, uarg, sizeof(fdd)))
			return -EFAULT;
		return ion_legacy_flush(ctx, 3, 0, fdd.fd);
	case ION_LEGACY_IOC_CUSTOM64:
	case ION_LEGACY_IOC_CUSTOM32:
	{
		unsigned long carg;
		unsigned int ccmd;
		int handle, fd;

		if (cmd == ION_LEGACY_IOC_CUSTOM64) {
			struct ion_legacy_custom64 c;

			if (copy_from_user(&c, uarg, sizeof(c)))
				return -EFAULT;
			ccmd = c.cmd;
			carg = c.arg;
		} else {
			struct ion_legacy_custom32 c;

			if (copy_from_user(&c, uarg, sizeof(c)))
				return -EFAULT;
			ccmd = c.cmd;
			carg = c.arg;
		}

		switch (ccmd) {
		case ION_LEGACY_CLEAN_CACHES64:
		case ION_LEGACY_INV_CACHES64:
		case ION_LEGACY_CLEAN_INV_CACHES64:
		{
			struct ion_legacy_flush64 f;

			if (copy_from_user(&f, (void __user *)carg, sizeof(f)))
				return -EFAULT;
			handle = f.handle;
			fd = f.fd;
			break;
		}
		case ION_LEGACY_CLEAN_CACHES32:
		case ION_LEGACY_INV_CACHES32:
		case ION_LEGACY_CLEAN_INV_CACHES32:
		{
			struct ion_legacy_flush32 f;

			if (copy_from_user(&f, (void __user *)carg, sizeof(f)))
				return -EFAULT;
			handle = f.handle;
			fd = f.fd;
			break;
		}
		default:
			return -ENOTTY;
		}
		return ion_legacy_flush(ctx, _IOC_NR(ccmd), handle, fd);
	}
	default:
		return -ENOIOCTLCMD;
	}
}

long ion_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	long legacy_ret;
	int ret = 0;
	unsigned int dir;
	union ion_ioctl_arg data;

	if (filp->private_data) {
		legacy_ret = ion_legacy_ioctl(filp, cmd, arg);
		if (legacy_ret != -ENOIOCTLCMD)
			return legacy_ret;
	}

	dir = ion_ioctl_dir(cmd);

	if (_IOC_SIZE(cmd) > sizeof(data))
		return -EINVAL;

	/*
	 * The copy_from_user is unconditional here for both read and write
	 * to do the validate. If there is no write for the ioctl, the
	 * buffer is cleared
	 */
	if (copy_from_user(&data, (void __user *)arg, _IOC_SIZE(cmd)))
		return -EFAULT;

	ret = validate_ioctl_arg(cmd, &data);
	if (ret) {
		pr_warn_once("%s: ioctl validate failed\n", __func__);
		return ret;
	}

	if (!(dir & _IOC_WRITE))
		memset(&data, 0, sizeof(data));

	switch (cmd) {
	case ION_IOC_ALLOC:
	{
		int fd;

		fd = ion_alloc_fd(data.allocation.len,
				  data.allocation.heap_id_mask,
				  data.allocation.flags);
		if (fd < 0)
			return fd;

		data.allocation.fd = fd;

		break;
	}
	case ION_IOC_HEAP_QUERY:
		ret = ion_query_heaps(&data.query);
		break;
	case ION_IOC_PREFETCH:
	{
		int ret;

		ret = ion_walk_heaps(data.prefetch_data.heap_id,
				     (enum ion_heap_type)
				     ION_HEAP_TYPE_SYSTEM_SECURE,
				     (void *)&data.prefetch_data,
				     ion_system_secure_heap_prefetch);
		if (ret)
			return ret;
		break;
	}
	case ION_IOC_DRAIN:
	{
		int ret;

		ret = ion_walk_heaps(data.prefetch_data.heap_id,
				     (enum ion_heap_type)
				     ION_HEAP_TYPE_SYSTEM_SECURE,
				     (void *)&data.prefetch_data,
				     ion_system_secure_heap_drain);

		if (ret)
			return ret;
		break;
	}
	default:
		return -ENOTTY;
	}

	if (dir & _IOC_READ) {
		if (copy_to_user((void __user *)arg, &data, _IOC_SIZE(cmd)))
			return -EFAULT;
	}
	return ret;
}
