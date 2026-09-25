// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2024, NVIDIA CORPORATION & AFFILIATES
 */
#include "iommufd_private.h"

/* Driver should use a per-structure helper in include/linux/iommufd.h */
int _iommufd_object_depend(struct iommufd_object *obj_dependent,
			   struct iommufd_object *obj_depended)
{
	/* Reject self dependency that dead locks */
	if (obj_dependent == obj_depended)
		return -EINVAL;
	/* Only support dependency between two objects of the same type */
	if (obj_dependent->type != obj_depended->type)
		return -EINVAL;

	refcount_inc(&obj_depended->users);
	return 0;
}
EXPORT_SYMBOL_NS_GPL(_iommufd_object_depend, "IOMMUFD");

/* Driver should use a per-structure helper in include/linux/iommufd.h */
void _iommufd_object_undepend(struct iommufd_object *obj_dependent,
			      struct iommufd_object *obj_depended)
{
	if (WARN_ON_ONCE(obj_dependent == obj_depended ||
			 obj_dependent->type != obj_depended->type))
		return;

	refcount_dec(&obj_depended->users);
}
EXPORT_SYMBOL_NS_GPL(_iommufd_object_undepend, "IOMMUFD");

/*
 * Allocate an @offset to return to user space to use for an mmap() syscall
 *
 * Driver should use a per-structure helper in include/linux/iommufd.h
 */
int _iommufd_alloc_mmap(struct iommufd_ctx *ictx, struct iommufd_object *owner,
			phys_addr_t mmio_addr, size_t length,
			unsigned long *offset)
{
	struct iommufd_mmap *immap;
	unsigned long startp;
	int rc;

	if (!PAGE_ALIGNED(mmio_addr))
		return -EINVAL;
	if (!length || !PAGE_ALIGNED(length))
		return -EINVAL;

	immap = kzalloc_obj(*immap);
	if (!immap)
		return -ENOMEM;
	immap->owner = owner;
	immap->length = length;
	immap->mmio_addr = mmio_addr;

	/* Skip the first page to ease caller identifying the returned offset */
	rc = mtree_alloc_range(&ictx->mt_mmap, &startp, immap, immap->length,
			       PAGE_SIZE, ULONG_MAX, GFP_KERNEL);
	if (rc < 0) {
		kfree(immap);
		return rc;
	}

	/* mmap() syscall will right-shift the offset in vma->vm_pgoff too */
	immap->vm_pgoff = startp >> PAGE_SHIFT;
	*offset = startp;
	return 0;
}
EXPORT_SYMBOL_NS_GPL(_iommufd_alloc_mmap, "IOMMUFD");

/* Driver should use a per-structure helper in include/linux/iommufd.h */
void _iommufd_destroy_mmap(struct iommufd_ctx *ictx,
			   struct iommufd_object *owner, unsigned long offset)
{
	struct iommufd_mmap *immap;

	immap = mtree_erase(&ictx->mt_mmap, offset);
	WARN_ON_ONCE(!immap || immap->owner != owner);
	kfree(immap);
}
EXPORT_SYMBOL_NS_GPL(_iommufd_destroy_mmap, "IOMMUFD");

struct device *iommufd_vdevice_to_device(struct iommufd_vdevice *vdev)
{
	return vdev->idev->dev;
}
EXPORT_SYMBOL_NS_GPL(iommufd_vdevice_to_device, "IOMMUFD");

/* Caller should xa_lock(&viommu->vdevs) to protect the return value */
struct device *iommufd_viommu_find_dev(struct iommufd_viommu *viommu,
				       unsigned long vdev_id)
{
	struct iommufd_vdevice *vdev;

	lockdep_assert_held(&viommu->vdevs.xa_lock);

	vdev = xa_load(&viommu->vdevs, vdev_id);
	return vdev ? iommufd_vdevice_to_device(vdev) : NULL;
}
EXPORT_SYMBOL_NS_GPL(iommufd_viommu_find_dev, "IOMMUFD");

/* Return -ENOENT if device is not associated to the vIOMMU */
int iommufd_viommu_get_vdev_id(struct iommufd_viommu *viommu,
			       struct device *dev, unsigned long *vdev_id)
{
	struct iommufd_vdevice *vdev;
	unsigned long index;
	int rc = -ENOENT;

	if (WARN_ON_ONCE(!vdev_id))
		return -EINVAL;

	xa_lock(&viommu->vdevs);
	xa_for_each(&viommu->vdevs, index, vdev) {
		if (iommufd_vdevice_to_device(vdev) == dev) {
			*vdev_id = vdev->virt_id;
			rc = 0;
			break;
		}
	}
	xa_unlock(&viommu->vdevs);
	return rc;
}
EXPORT_SYMBOL_NS_GPL(iommufd_viommu_get_vdev_id, "IOMMUFD");

/*
 * Typically called in driver's threaded IRQ handler.
 * The @type and @event_data must be defined in include/uapi/linux/iommufd.h
 */
int iommufd_viommu_report_event(struct iommufd_viommu *viommu,
				enum iommu_veventq_type type, void *event_data,
				size_t data_len)
{
	struct iommufd_veventq *veventq;
	struct iommufd_vevent *vevent;
	int rc = 0;

	if (WARN_ON_ONCE(!data_len || !event_data))
		return -EINVAL;

	down_read(&viommu->veventqs_rwsem);

	veventq = iommufd_viommu_find_veventq(viommu, type);
	if (!veventq) {
		rc = -EOPNOTSUPP;
		goto out_unlock_veventqs;
	}

	/* Pre-allocate to avoid GFP_ATOMIC; use GFP_NOWAIT to avoid sleeping */
	vevent = kzalloc_flex(*vevent, event_data, data_len, GFP_NOWAIT);
	if (!vevent) {
		spin_lock(&veventq->common.lock);
		vevent = &veventq->lost_events_header;
		rc = -ENOMEM;
		goto out_set_header;
	}

	spin_lock(&veventq->common.lock);
	if (veventq->num_events == veventq->depth) {
		kfree(vevent);
		vevent = &veventq->lost_events_header;
		goto out_set_header;
	}
	vevent->data_len = data_len;
	memcpy(vevent->event_data, event_data, data_len);
	veventq->num_events++;

out_set_header:
	iommufd_vevent_handler(veventq, vevent);
	spin_unlock(&veventq->common.lock);
out_unlock_veventqs:
	up_read(&viommu->veventqs_rwsem);
	return rc;
}
EXPORT_SYMBOL_NS_GPL(iommufd_viommu_report_event, "IOMMUFD");

#ifdef CONFIG_IRQ_MSI_IOMMU
static bool iommufd_sw_msi_range_index(const struct iommufd_sw_msi_map *map,
				       const struct iommufd_sw_msi_map *base_map,
				       unsigned int nr_addrs, unsigned int *index)
{
	if (map->sw_msi_start != base_map->sw_msi_start || map->pgoff < base_map->pgoff)
		return false;

	*index = map->pgoff - base_map->pgoff;
	return *index < nr_addrs;
}

/*
 * Get an iommufd_sw_msi_map for the msi physical addresses requested by the irq
 * layer. The mapping to IOVA is global to the iommufd file descriptor, every
 * domain that is attached to a device using the same MSI parameters will use
 * the same contiguous IOVA range.
 */
static struct iommufd_sw_msi_map *
iommufd_sw_msi_get_map(struct iommufd_ctx *ictx, const phys_addr_t *phys_addrs,
		       unsigned int nr_addrs, const struct iommufd_sw_msi_range *sw_msi_range)
{
	struct iommufd_sw_msi_map *cur, *msi_map;
	unsigned int nr_found;

	lockdep_assert_held(&ictx->sw_msi_lock);

	list_for_each_entry(msi_map, &ictx->sw_msi_list, sw_msi_item) {
		if (msi_map->sw_msi_start != sw_msi_range->start ||
		    msi_map->msi_addr != phys_addrs[0])
			continue;
		if (msi_map->range_size != nr_addrs * PAGE_SIZE)
			continue;
		if (msi_map->pgoff > sw_msi_range->length / PAGE_SIZE ||
		    nr_addrs > sw_msi_range->length / PAGE_SIZE - msi_map->pgoff)
			continue;

		nr_found = 0;
		list_for_each_entry(cur, &ictx->sw_msi_list, sw_msi_item) {
			unsigned int index;

			if (!iommufd_sw_msi_range_index(cur, msi_map, nr_addrs, &index))
				continue;
			if (cur->msi_addr != phys_addrs[index])
				break;
			nr_found++;
		}
		if (nr_found == nr_addrs)
			return msi_map;
	}
	return NULL;
}

static int iommufd_sw_msi_check_alloc(struct iommufd_ctx *ictx,
				      const struct iommufd_sw_msi_range *sw_msi_range,
				      unsigned int first_pgoff, unsigned int nr_addrs,
				      size_t *range_size)
{
	unsigned long max_iova_pgoff;
	unsigned int last_pgoff;
	unsigned int last_id;
	size_t range_pages;

	if (!nr_addrs)
		return -EINVAL;
	if (sw_msi_range->start > ULONG_MAX)
		return -EOVERFLOW;

	range_pages = sw_msi_range->length / PAGE_SIZE;
	max_iova_pgoff = (ULONG_MAX - sw_msi_range->start) / PAGE_SIZE;

	if (check_add_overflow(ictx->sw_msi_id, nr_addrs - 1, &last_id) ||
	    last_id > IOMMUFD_SW_MSI_MAX_ID ||
	    check_add_overflow(first_pgoff, nr_addrs - 1, &last_pgoff) ||
	    last_pgoff > max_iova_pgoff ||
	    check_mul_overflow((size_t)nr_addrs, PAGE_SIZE, range_size))
		return -EOVERFLOW;

	if (last_pgoff >= range_pages)
		return -ENOSPC;

	return 0;
}

static struct iommufd_sw_msi_map *
iommufd_sw_msi_alloc_map(struct iommufd_ctx *ictx, const phys_addr_t *phys_addrs,
			 unsigned int nr_addrs, const struct iommufd_sw_msi_range *sw_msi_range,
			 struct list_head *new_msi_maps)
{
	struct iommufd_sw_msi_map *cur, *first_map = NULL;
	unsigned int next_pgoff = 0;
	unsigned int i;
	size_t size;
	int rc;

	lockdep_assert_held(&ictx->sw_msi_lock);

	list_for_each_entry(cur, &ictx->sw_msi_list, sw_msi_item) {
		if (cur->sw_msi_start != sw_msi_range->start)
			continue;
		if (cur->pgoff == UINT_MAX)
			return ERR_PTR(-EOVERFLOW);
		next_pgoff = max(next_pgoff, cur->pgoff + 1);
	}

	rc = iommufd_sw_msi_check_alloc(ictx, sw_msi_range, next_pgoff, nr_addrs, &size);
	if (rc)
		return ERR_PTR(rc);

	for (i = 0; i < nr_addrs; i++) {
		cur = kzalloc_obj(*cur);
		if (!cur)
			goto err_free;

		cur->sw_msi_start = sw_msi_range->start;
		cur->msi_addr = phys_addrs[i];
		cur->pgoff = next_pgoff + i;
		cur->id = ictx->sw_msi_id + i;
		if (!i) {
			cur->range_size = size;
			first_map = cur;
		}
		list_add_tail(&cur->sw_msi_item, new_msi_maps);
	}

	return first_map;

err_free:
	while (!list_empty(new_msi_maps)) {
		cur = list_first_entry(new_msi_maps, typeof(*cur), sw_msi_item);
		list_del(&cur->sw_msi_item);
		kfree(cur);
	}
	return ERR_PTR(-ENOMEM);
}

static int iommufd_sw_msi_install_one(struct iommufd_ctx *ictx,
				      struct iommufd_hwpt_paging *hwpt_paging,
				      struct iommufd_sw_msi_map *msi_map)
{
	unsigned long iova;
	int rc;

	lockdep_assert_held(&ictx->sw_msi_lock);

	if (iommufd_sw_msi_maps_test_bit(&hwpt_paging->present_sw_msi, msi_map->id))
		return 0;

	iova = msi_map->sw_msi_start + msi_map->pgoff * PAGE_SIZE;
	rc = iommufd_sw_msi_maps_ensure(&hwpt_paging->present_sw_msi, msi_map->id);
	if (rc)
		return rc;

	rc = iommu_map(hwpt_paging->common.domain, iova,
		       msi_map->msi_addr, PAGE_SIZE,
		       IOMMU_WRITE | IOMMU_READ | IOMMU_MMIO,
		       GFP_KERNEL_ACCOUNT);
	if (rc)
		return rc;
	__set_bit(msi_map->id, hwpt_paging->present_sw_msi.bitmap);
	return 0;
}

int iommufd_sw_msi_install(struct iommufd_ctx *ictx,
			   struct iommufd_hwpt_paging *hwpt_paging,
			   struct iommufd_sw_msi_map *base_map)
{
	struct iommufd_sw_msi_map *msi_map;
	struct list_head *msi_maps = &ictx->sw_msi_list;
	unsigned long *newly_mapped;
	unsigned int nr_addrs = base_map->range_size ? base_map->range_size / PAGE_SIZE : 1;
	unsigned int nr_found = 0;
	unsigned int index;
	int rc = 0;

	newly_mapped = bitmap_zalloc(nr_addrs, GFP_KERNEL_ACCOUNT);
	if (!newly_mapped)
		return -ENOMEM;

	list_for_each_entry(msi_map, msi_maps, sw_msi_item) {
		if (!iommufd_sw_msi_range_index(msi_map, base_map, nr_addrs, &index))
			continue;
		if (iommufd_sw_msi_maps_test_bit(&hwpt_paging->present_sw_msi, msi_map->id)) {
			nr_found++;
			continue;
		}
		rc = iommufd_sw_msi_install_one(ictx, hwpt_paging, msi_map);
		if (rc)
			goto err_unmap;
		__set_bit(index, newly_mapped);
		nr_found++;
	}
	if (nr_found != nr_addrs) {
		rc = -EINVAL;
		goto err_unmap;
	}

	bitmap_free(newly_mapped);
	return 0;

err_unmap:
	list_for_each_entry(msi_map, msi_maps, sw_msi_item) {
		unsigned long iova;

		if (!iommufd_sw_msi_range_index(msi_map, base_map, nr_addrs, &index) ||
		    !test_bit(index, newly_mapped))
			continue;

		iova = msi_map->sw_msi_start + msi_map->pgoff * PAGE_SIZE;
		WARN_ON_ONCE(iommu_unmap(hwpt_paging->common.domain, iova, PAGE_SIZE) != PAGE_SIZE);
		__clear_bit(msi_map->id, hwpt_paging->present_sw_msi.bitmap);
	}
	bitmap_free(newly_mapped);
	return rc;
}
EXPORT_SYMBOL_NS_GPL(iommufd_sw_msi_install, "IOMMUFD_INTERNAL");

/*
 * Called by the irq code if the platform translates the MSI address through the
 * IOMMU. msi_addr is the physical address of the MSI page. iommufd will
 * allocate a fd global iova for the physical page that is the same on all
 * domains and devices.
 */
int iommufd_sw_msi(struct iommu_domain *domain, struct msi_desc *desc,
		   phys_addr_t msi_addr)
{
	struct device *dev = msi_desc_to_dev(desc);
	struct iommufd_hwpt_paging *hwpt_paging;
	struct iommu_attach_handle *raw_handle;
	struct iommufd_attach_handle *handle;
	struct iommufd_sw_msi_map *msi_map;
	struct iommufd_ctx *ictx;
	LIST_HEAD(new_msi_maps);
	unsigned long iova;
	phys_addr_t phys_addr;
	int rc;

	/*
	 * It is safe to call iommu_attach_handle_get() here because the iommu
	 * core code invokes this under the group mutex which also prevents any
	 * change of the attach handle for the duration of this function.
	 */
	iommu_group_mutex_assert(dev);

	raw_handle =
		iommu_attach_handle_get(dev->iommu_group, IOMMU_NO_PASID, 0);
	if (IS_ERR(raw_handle))
		return 0;
	hwpt_paging = find_hwpt_paging(domain->iommufd_hwpt);

	handle = to_iommufd_handle(raw_handle);
	/* No IOMMU_RESV_SW_MSI means no change to the msi_msg */
	if (handle->idev->igroup->sw_msi_range.start == PHYS_ADDR_MAX)
		return 0;

	ictx = handle->idev->ictx;
	guard(mutex)(&ictx->sw_msi_lock);
	/*
	 * The input msi_addr is the exact byte offset of the MSI doorbell, we
	 * assume the caller has checked that it is contained with a MMIO region
	 * that is secure to map at PAGE_SIZE.
	 */
	phys_addr = msi_addr & PAGE_MASK;
	msi_map = iommufd_sw_msi_get_map(ictx, &phys_addr, 1, &handle->idev->igroup->sw_msi_range);
	if (!msi_map)
		msi_map = iommufd_sw_msi_alloc_map(ictx, &phys_addr, 1,
						   &handle->idev->igroup->sw_msi_range,
						   &new_msi_maps);
	if (IS_ERR(msi_map))
		return PTR_ERR(msi_map);

	rc = iommufd_sw_msi_maps_ensure(&handle->idev->igroup->required_sw_msi,
					msi_map->id);
	if (rc)
		goto err_free;

	rc = iommufd_sw_msi_install(ictx, hwpt_paging, msi_map);
	if (rc)
		goto err_free;
	__set_bit(msi_map->id, handle->idev->igroup->required_sw_msi.bitmap);

	if (!list_empty(&new_msi_maps)) {
		list_splice_tail_init(&new_msi_maps, &ictx->sw_msi_list);
		ictx->sw_msi_id++;
	}

	iova = msi_map->sw_msi_start + msi_map->pgoff * PAGE_SIZE;
	msi_desc_set_iommu_msi_iova(desc, iova, PAGE_SHIFT);
	return 0;

err_free:
	while (!list_empty(&new_msi_maps)) {
		msi_map = list_first_entry(&new_msi_maps, typeof(*msi_map), sw_msi_item);
		list_del(&msi_map->sw_msi_item);
		kfree(msi_map);
	}
	return rc;
}
EXPORT_SYMBOL_NS_GPL(iommufd_sw_msi, "IOMMUFD");
#endif

MODULE_DESCRIPTION("iommufd code shared with builtin modules");
MODULE_IMPORT_NS("IOMMUFD_INTERNAL");
MODULE_LICENSE("GPL");
