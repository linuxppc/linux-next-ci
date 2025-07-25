// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2023 Intel Corporation.
 */
#include <linux/vfio.h>
#include <linux/iommufd.h>

#include "vfio.h"

static dev_t device_devt;

void vfio_init_device_cdev(struct vfio_device *device)
{
	device->device.devt = MKDEV(MAJOR(device_devt), device->index);
	cdev_init(&device->cdev, &vfio_device_fops);
	device->cdev.owner = THIS_MODULE;
}

/*
 * device access via the fd opened by this function is blocked until
 * .open_device() is called successfully during BIND_IOMMUFD.
 */
int vfio_device_fops_cdev_open(struct inode *inode, struct file *filep)
{
	struct vfio_device *device = container_of(inode->i_cdev,
						  struct vfio_device, cdev);
	struct vfio_device_file *df;
	int ret;

	/* Paired with the put in vfio_device_fops_release() */
	if (!vfio_device_try_get_registration(device))
		return -ENODEV;

	df = vfio_allocate_device_file(device);
	if (IS_ERR(df)) {
		ret = PTR_ERR(df);
		goto err_put_registration;
	}

	filep->private_data = df;

	/*
	 * Use the pseudo fs inode on the device to link all mmaps
	 * to the same address space, allowing us to unmap all vmas
	 * associated to this device using unmap_mapping_range().
	 */
	filep->f_mapping = device->inode->i_mapping;

	return 0;

err_put_registration:
	vfio_device_put_registration(device);
	return ret;
}

static void vfio_df_get_kvm_safe(struct vfio_device_file *df)
{
	spin_lock(&df->kvm_ref_lock);
	vfio_device_get_kvm_safe(df->device, df->kvm);
	spin_unlock(&df->kvm_ref_lock);
}

static int vfio_df_check_token(struct vfio_device *device,
			       const struct vfio_device_bind_iommufd *bind)
{
	uuid_t uuid;

	if (!device->ops->match_token_uuid) {
		if (bind->flags & VFIO_DEVICE_BIND_FLAG_TOKEN)
			return -EINVAL;
		return 0;
	}

	if (!(bind->flags & VFIO_DEVICE_BIND_FLAG_TOKEN))
		return device->ops->match_token_uuid(device, NULL);

	if (copy_from_user(&uuid, u64_to_user_ptr(bind->token_uuid_ptr),
			   sizeof(uuid)))
		return -EFAULT;
	return device->ops->match_token_uuid(device, &uuid);
}

long vfio_df_ioctl_bind_iommufd(struct vfio_device_file *df,
				struct vfio_device_bind_iommufd __user *arg)
{
	const u32 VALID_FLAGS = VFIO_DEVICE_BIND_FLAG_TOKEN;
	struct vfio_device *device = df->device;
	struct vfio_device_bind_iommufd bind;
	unsigned long minsz;
	u32 user_size;
	int ret;

	static_assert(__same_type(arg->out_devid, df->devid));

	minsz = offsetofend(struct vfio_device_bind_iommufd, out_devid);

	ret = get_user(user_size, &arg->argsz);
	if (ret)
		return ret;
	if (user_size < minsz)
		return -EINVAL;
	ret = copy_struct_from_user(&bind, minsz, arg, user_size);
	if (ret)
		return ret;

	if (bind.iommufd < 0 || bind.flags & ~VALID_FLAGS)
		return -EINVAL;

	/* BIND_IOMMUFD only allowed for cdev fds */
	if (df->group)
		return -EINVAL;

	ret = vfio_device_block_group(device);
	if (ret)
		return ret;

	mutex_lock(&device->dev_set->lock);
	/* one device cannot be bound twice */
	if (df->access_granted) {
		ret = -EINVAL;
		goto out_unlock;
	}

	ret = vfio_df_check_token(device, &bind);
	if (ret)
		goto out_unlock;

	df->iommufd = iommufd_ctx_from_fd(bind.iommufd);
	if (IS_ERR(df->iommufd)) {
		ret = PTR_ERR(df->iommufd);
		df->iommufd = NULL;
		goto out_unlock;
	}

	/*
	 * Before the device open, get the KVM pointer currently
	 * associated with the device file (if there is) and obtain
	 * a reference.  This reference is held until device closed.
	 * Save the pointer in the device for use by drivers.
	 */
	vfio_df_get_kvm_safe(df);

	ret = vfio_df_open(df);
	if (ret)
		goto out_put_kvm;

	ret = copy_to_user(&arg->out_devid, &df->devid,
			   sizeof(df->devid)) ? -EFAULT : 0;
	if (ret)
		goto out_close_device;

	device->cdev_opened = true;
	/*
	 * Paired with smp_load_acquire() in vfio_device_fops::ioctl/
	 * read/write/mmap
	 */
	smp_store_release(&df->access_granted, true);
	mutex_unlock(&device->dev_set->lock);
	return 0;

out_close_device:
	vfio_df_close(df);
out_put_kvm:
	vfio_device_put_kvm(device);
	iommufd_ctx_put(df->iommufd);
	df->iommufd = NULL;
out_unlock:
	mutex_unlock(&device->dev_set->lock);
	vfio_device_unblock_group(device);
	return ret;
}

void vfio_df_unbind_iommufd(struct vfio_device_file *df)
{
	struct vfio_device *device = df->device;

	/*
	 * In the time of close, there is no contention with another one
	 * changing this flag.  So read df->access_granted without lock
	 * and no smp_load_acquire() is ok.
	 */
	if (!df->access_granted)
		return;

	mutex_lock(&device->dev_set->lock);
	vfio_df_close(df);
	vfio_device_put_kvm(device);
	iommufd_ctx_put(df->iommufd);
	device->cdev_opened = false;
	mutex_unlock(&device->dev_set->lock);
	vfio_device_unblock_group(device);
}

int vfio_df_ioctl_attach_pt(struct vfio_device_file *df,
			    struct vfio_device_attach_iommufd_pt __user *arg)
{
	struct vfio_device_attach_iommufd_pt attach;
	struct vfio_device *device = df->device;
	unsigned long minsz, xend = 0;
	int ret;

	minsz = offsetofend(struct vfio_device_attach_iommufd_pt, pt_id);

	if (copy_from_user(&attach, arg, minsz))
		return -EFAULT;

	if (attach.argsz < minsz)
		return -EINVAL;

	if (attach.flags & ~VFIO_DEVICE_ATTACH_PASID)
		return -EINVAL;

	if (attach.flags & VFIO_DEVICE_ATTACH_PASID) {
		if (!device->ops->pasid_attach_ioas)
			return -EOPNOTSUPP;
		xend = offsetofend(struct vfio_device_attach_iommufd_pt, pasid);
	}

	if (xend) {
		if (attach.argsz < xend)
			return -EINVAL;

		if (copy_from_user((void *)&attach + minsz,
				   (void __user *)arg + minsz, xend - minsz))
			return -EFAULT;
	}

	mutex_lock(&device->dev_set->lock);
	if (attach.flags & VFIO_DEVICE_ATTACH_PASID)
		ret = device->ops->pasid_attach_ioas(device,
						     attach.pasid,
						     &attach.pt_id);
	else
		ret = device->ops->attach_ioas(device, &attach.pt_id);
	if (ret)
		goto out_unlock;

	if (copy_to_user(&arg->pt_id, &attach.pt_id, sizeof(attach.pt_id))) {
		ret = -EFAULT;
		goto out_detach;
	}
	mutex_unlock(&device->dev_set->lock);

	return 0;

out_detach:
	device->ops->detach_ioas(device);
out_unlock:
	mutex_unlock(&device->dev_set->lock);
	return ret;
}

int vfio_df_ioctl_detach_pt(struct vfio_device_file *df,
			    struct vfio_device_detach_iommufd_pt __user *arg)
{
	struct vfio_device_detach_iommufd_pt detach;
	struct vfio_device *device = df->device;
	unsigned long minsz, xend = 0;

	minsz = offsetofend(struct vfio_device_detach_iommufd_pt, flags);

	if (copy_from_user(&detach, arg, minsz))
		return -EFAULT;

	if (detach.argsz < minsz)
		return -EINVAL;

	if (detach.flags & ~VFIO_DEVICE_DETACH_PASID)
		return -EINVAL;

	if (detach.flags & VFIO_DEVICE_DETACH_PASID) {
		if (!device->ops->pasid_detach_ioas)
			return -EOPNOTSUPP;
		xend = offsetofend(struct vfio_device_detach_iommufd_pt, pasid);
	}

	if (xend) {
		if (detach.argsz < xend)
			return -EINVAL;

		if (copy_from_user((void *)&detach + minsz,
				   (void __user *)arg + minsz, xend - minsz))
			return -EFAULT;
	}

	mutex_lock(&device->dev_set->lock);
	if (detach.flags & VFIO_DEVICE_DETACH_PASID)
		device->ops->pasid_detach_ioas(device, detach.pasid);
	else
		device->ops->detach_ioas(device);
	mutex_unlock(&device->dev_set->lock);

	return 0;
}

static char *vfio_device_devnode(const struct device *dev, umode_t *mode)
{
	return kasprintf(GFP_KERNEL, "vfio/devices/%s", dev_name(dev));
}

int vfio_cdev_init(struct class *device_class)
{
	device_class->devnode = vfio_device_devnode;
	return alloc_chrdev_region(&device_devt, 0,
				   MINORMASK + 1, "vfio-dev");
}

void vfio_cdev_cleanup(void)
{
	unregister_chrdev_region(device_devt, MINORMASK + 1);
}
