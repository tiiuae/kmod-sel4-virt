#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/mutex.h>
#include <linux/list.h>

#include "sel4_virt_drv.h"
#include "sel4_vmm_pool.h"

/* The purpose of the vmm component is to form VM slots of the matching
 * control and ram buffers. As a bonus, the component provides a sense of
 * dynamism for lower levels.
 *
 * The vmm buffers and are matched by `vmm_id`, an unsigned value between
 * 0-0xfe. The ID is determined by the caller - it is up to caller to figure
 * out how to identify unique vmm_ids.
 *
 * Once the matching pair of vmm and ram buffers have been registered, a new
 * VM slot is made available.
 */

/* Lock for module's resources */
DEFINE_MUTEX(sel4_vmmpool_lock);
LIST_HEAD(sel4_vmmpool);

struct sel4_vmmpool_entry {
	struct list_head pool;
	struct sel4_vmm *vmm;
};

static bool sel4_mem_map_valid(struct sel4_mem_map *mem)
{
	if (WARN_ON(IS_ERR_OR_NULL(mem))) {
		return false;
	}

	return (mem->size && mem->service_vm_va);
}

static bool sel4_vmm_valid(struct sel4_vmm *vmm)
{
	if (WARN_ON(IS_ERR_OR_NULL(vmm))) {
		return false;
	}

	return sel4_mem_map_valid(&vmm->ram);
}

int sel4_vmmpool_add(struct sel4_vmm *vmm)
{
	struct sel4_vmmpool_entry *entry;
	int rc = 0;

	if (!sel4_vmm_valid(vmm)) {
		return -EINVAL;
	}

	mutex_lock(&sel4_vmmpool_lock);

	list_for_each_entry(entry, &sel4_vmmpool, pool) {
		if (WARN_ON(entry->vmm->id == vmm->id)) {
			rc = -EALREADY;
			goto out_unlock;
		}
	}

	entry = kzalloc(sizeof(struct sel4_vmmpool_entry), GFP_KERNEL);
	if (!entry) {
		rc = -ENOMEM;
		goto out_unlock;
	}

	entry->vmm = vmm;
	list_add(&entry->pool, &sel4_vmmpool);

out_unlock:
	mutex_unlock(&sel4_vmmpool_lock);

	return rc;
}

struct sel4_vmm *sel4_vmmpool_remove(int id)
{
	struct sel4_vmmpool_entry *entry, *tmp;
	struct sel4_vmm *vmm = NULL;

	mutex_lock(&sel4_vmmpool_lock);
	list_for_each_entry_safe(entry, tmp, &sel4_vmmpool, pool) {
		if (entry->vmm->id == id) {
			vmm = entry->vmm;
			list_del(&entry->pool);
			kfree(entry);
			break;
		}
	}
	mutex_unlock(&sel4_vmmpool_lock);

	return vmm;
}

struct sel4_vmm *sel4_vmmpool_get(resource_size_t ram_size)
{
	struct sel4_vmmpool_entry *entry, *tmp;
	struct sel4_vmm *vmm = NULL;
	if (WARN_ON(!ram_size)) {
		return ERR_PTR(-EINVAL);
	}

	mutex_lock(&sel4_vmmpool_lock);

	list_for_each_entry_safe(entry, tmp, &sel4_vmmpool, pool) {
		if (entry->vmm->ram.size >= ram_size) {
			vmm = entry->vmm;
			list_del(&entry->pool);
			kfree(entry);
			break;
		}
	}

	mutex_unlock(&sel4_vmmpool_lock);

	return vmm;
}

