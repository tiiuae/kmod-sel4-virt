#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/pci.h>
#include <linux/pci_ids.h>
#include <linux/mutex.h>
#include <linux/list.h>

#include "sel4_virt_drv.h"
#include "sel4_rpc.h"
#include "sel4_vmm_pool.h"

#define PCI_SEL4_DEVICE_ID 0xa111

/* For now we distinguish control and guest RAM region by name */
#define SEL4_DEVICE_NAME_REGISTER_OFFSET 2
#define SEL4_DEVICE_NAME_MAX_LEN 50

/* We have two types of dataports, control and ram */
#define SEL4_DATAPORT_IOBUF	0
#define SEL4_DATAPORT_RAM	1
#define SEL4_DATAPORT_LAST	2

/* Dataport states: when the dataport is associated with vmm, the state is
 * active. When dataport still in use is going to be removed, the state is
 * changed to 'removing', and then the core is notified about the removal. The
 * core does its thin, and issues the destroy callback, that handles vmm
 * removal and sets the states of the associated dataports to 'removed'.
 */
#define SEL4_DATAPORT_ALLOCATED 0
#define SEL4_DATAPORT_ACTIVE	1
#define SEL4_DATAPORT_REMOVING	2
#define SEL4_DATAPORT_REMOVED	3

char *dataport_match[SEL4_DATAPORT_LAST] = {
	"guest-iobuf",
	"guest-ram",
};

DEFINE_MUTEX(sel4_dataports_lock);
LIST_HEAD(sel4_dataports);

struct sel4_dataport {
	struct list_head	list;
	/* determined by the hypervisor */
	int			vmid;
	int			dataport_type;
	char			name[SEL4_DEVICE_NAME_MAX_LEN + 1];
	/* 0 = eventbar, 1 = dataport memory */
	struct sel4_mem_map	mem[2];
	struct pci_dev		*dev;
	/* id as understood by the core */
	int			vmm_id;
	int			state;
};

/**
 * extract_dataport_type - extracts the dataport type from the name
 * @name: name of the dataport
 * @len: length of the name
 *
 * Returns SEL4_DATAPORT_{CONTROL,RAM} on success. On error negative errno is
 * returned.
 */
static int extract_dataport_type(char *name, size_t len)
{
	int i;

	for (i = 0; i < SEL4_DATAPORT_LAST; i++) {
		if (!strncmp(dataport_match[i], name,
			     min(strlen(dataport_match[i]), len))) {
			return i;
		}
	}

	return -EINVAL;
}

/**
 * extract_vmid - extracts the vmid from the name
 * @name: name of the dataport
 * @len: length of the name
 *
 * On success, returns 0 or positive vmid. Otherwise returns negative errno.
 */
static int extract_vmid(char *name, size_t len)
{
	int vmid;
	int dataport_type = extract_dataport_type(name, len);

	if (dataport_type < 0) {
		/* pass on the error */
		return dataport_type;
	}

	if (!kstrtoint(name + min(strlen(dataport_match[dataport_type]) + 1, len),
		       10, &vmid)) {
		return vmid;
	}

	return -EINVAL;
}

/**
 * set_dataports_state - set state for associated dataports
 * @vmm_id: id of the vmm which the dataports are bound to
 * @state: one of the SEL4_DATAPORT_{ALLOCATED,ACTIVE,REMOVING/REMOVED}
 */
static void set_dataports_state(int vmm_id, int state)
{
	struct sel4_dataport *entry;

	/* set state for all dataports that are used by vmm */
	list_for_each_entry(entry, &sel4_dataports, list) {
		if (entry->vmm_id == vmm_id)
			entry->state = state;
	}
}

/**
 * dataports_active - return true when all associated dataports are active
 * @vmm_id: id of the vmm which the dataports are bound to
 *
 * Returns true if all dataports associated active. Otherwise returns false.
 * Also returns false when no matching dataports are found.
 */
static bool dataports_active(int vmm_id)
{
	struct sel4_dataport *entry;
	bool found = false;

	list_for_each_entry(entry, &sel4_dataports, list) {
		if (entry->vmm_id == vmm_id) {
			found = true;
			if (entry->state != SEL4_DATAPORT_ACTIVE)
				return false;
		}
	}

	return (found) ? true : false;
}

static irqreturn_t sel4_pci_irqhandler(int irq, struct sel4_vmm *vmm)
{
	struct sel4_rpc *rpc = vmm->private;
	struct sel4_dataport *dataport = rpc->private;
	uint32_t *event_bar = dataport->mem[0].service_vm_va;
	u32 val;

	val = readl(&event_bar[1]);
	if (val == 0) {
		return IRQ_NONE;
	}

	// FIXME: save eventbar value
	writel(0, &event_bar[1]);

	return IRQ_HANDLED;
}

static void sel4_pci_doorbell(void *private)
{
	struct sel4_dataport *dataport = private;
	((uint32_t *) dataport->mem[0].service_vm_va)[0] = 1;
}

struct sel4_vmm_ops sel4_test_vmm_ops = {
	.start_vm = sel4_rpc_op_start_vm,
	.create_vpci_device = sel4_rpc_op_create_vpci_device,
	.destroy_vpci_device = sel4_rpc_op_destroy_vpci_device,
	.set_irqline = sel4_rpc_op_set_irqline,
	.upcall_irqhandler = sel4_pci_irqhandler,
	.notify_io_handled = sel4_rpc_op_notify_io_handled,
};

static int sel4_pci_vmm_create(int id, struct sel4_dataport * dataports[])
{
	struct sel4_vmm *vmm;
	struct sel4_rpc *rpc;
	int rc = 0;

	vmm = sel4_vmm_alloc(sel4_test_vmm_ops);
	if (IS_ERR_OR_NULL(vmm)) {
		return PTR_ERR(vmm);
	}

	vmm->id = id;

	vmm->irq = dataports[SEL4_DATAPORT_IOBUF]->dev->irq;
	vmm->irq_flags = IRQF_SHARED;

	vmm->iobuf = dataports[SEL4_DATAPORT_IOBUF]->mem[1];

	rpc = sel4_rpc_create(tx_queue(dataports[SEL4_DATAPORT_IOBUF]->mem[1].service_vm_va),
			      rx_queue(dataports[SEL4_DATAPORT_IOBUF]->mem[1].service_vm_va),
			      sel4_pci_doorbell,
			      dataports[SEL4_DATAPORT_IOBUF]);
	if (IS_ERR(rpc)) {
		rc = PTR_ERR(rpc);
		goto free_vmm;
	}

	vmm->ram = dataports[SEL4_DATAPORT_RAM]->mem[1];
	vmm->private = rpc;

	dataports[SEL4_DATAPORT_IOBUF]->vmm_id = vmm->id;
	dataports[SEL4_DATAPORT_RAM]->vmm_id = vmm->id;

	dataports[SEL4_DATAPORT_IOBUF]->state = SEL4_DATAPORT_ACTIVE;
	dataports[SEL4_DATAPORT_RAM]->state = SEL4_DATAPORT_ACTIVE;

	rc = sel4_vmmpool_add(vmm);
	if (rc)
		goto destroy_rpc;

	return rc;

destroy_rpc:
	sel4_rpc_destroy(rpc);

free_vmm:
	kfree(vmm);

	return rc;
}

static void sel4_pci_vmm_destroy(struct sel4_vmm *vmm)
{
	if (WARN_ON(!vmm || !vmm->private))
		return;

	sel4_rpc_destroy(vmm->private);
	kfree(vmm);
}

static int sel4_pci_probe(struct pci_dev *dev,
                          const struct pci_device_id *id)
{
	struct sel4_dataport *dataport, *entry;
	struct sel4_dataport *dataports[SEL4_DATAPORT_LAST] = { NULL, NULL };
	int last_bar = -1;
	int rc = 0;
	int i = 0;
	uint32_t *event_bar;

	dataport = kzalloc(sizeof(*dataport), GFP_KERNEL);
	if (!dataport) {
		return -ENOMEM;
	}
	dataport->dev = dev;
	dataport->vmm_id = -1;
	dataport->state = SEL4_DATAPORT_ALLOCATED;

	if (pci_enable_device(dev)) {
		goto free_dataport;
	}

	if (pci_request_regions(dev, "dataport")) {
		goto disable_pci;
	}

	for (i = 0; i < 2; i++) {
		dataport->mem[i].addr = pci_resource_start(dev, i);
		if (!dataport->mem[i].addr) {
			/* We assume the first NULL bar is the end
			 * Implying that all dataports are passed sequentially (i.e. no gaps) */
			rc = 1;
			break;
		}

		dataport->mem[i].service_vm_va = ioremap_cache(pci_resource_start(dev, i),
							       pci_resource_len(dev, i));
		if (!dataport->mem[i].service_vm_va) {
			rc = 1;
			break;
		}
		dataport->mem[i].size = pci_resource_len(dev, i);
		dataport->mem[i].type = SEL4_MEM_IOVA;

		last_bar = i;
	}

	/* We assume the event bar BAR0 always exists, even if the PCI device does
	 * not use events. */
	if (rc || last_bar < 0) {
		goto unmap_bars;
	}

	/* The format of the name must be:
	 * <buftype>-<vmid>
	 *
	 * where 'buftype' is 'guest-iobuf' or 'guest-ram', and 'vmid' is
	 * positive integer distinguishing different VMs.
	 */
	event_bar = dataport->mem[0].service_vm_va;
	strncpy(dataport->name, (char *)&event_bar[SEL4_DEVICE_NAME_REGISTER_OFFSET], SEL4_DEVICE_NAME_MAX_LEN);
	dataport->name[SEL4_DEVICE_NAME_MAX_LEN] = '\0'; /* for kstrtoint */

	dataport->vmid = extract_vmid(dataport->name, strlen(dataport->name));
	if (dataport->vmid < 0) {
		goto unmap_bars;
	}

	dataport->dataport_type = extract_dataport_type(dataport->name, strlen(dataport->name));
	if (dataport->dataport_type < 0) {
		goto unmap_bars;
	}

	mutex_lock(&sel4_dataports_lock);
	/* ensure no duplicates */
	list_for_each_entry(entry, &sel4_dataports, list) {
		if (entry->vmid == dataport->vmid &&
		    entry->dataport_type == dataport->dataport_type) {
			mutex_unlock(&sel4_dataports_lock);
			goto unmap_bars;
		}
	}

	/* check if matching memory counterpart */
	list_for_each_entry(entry, &sel4_dataports, list) {
		if (entry->vmid == dataport->vmid &&
		    entry->dataport_type != dataport->dataport_type &&
		    entry->dataport_type < SEL4_DATAPORT_LAST) {
			dataports[entry->dataport_type] = entry;
		}
	}
	dataports[dataport->dataport_type] = dataport;

	if (dataports[SEL4_DATAPORT_IOBUF] &&
	    dataports[SEL4_DATAPORT_RAM]) {
		rc = sel4_pci_vmm_create(dataport->vmid, dataports);
		if (rc) {
			mutex_unlock(&sel4_dataports_lock);
			goto unmap_bars;
		}
	}

	list_add(&dataport->list, &sel4_dataports);
	mutex_unlock(&sel4_dataports_lock);

	pci_set_drvdata(dev, dataport);

	pci_info(dev, "%s initialized\n", dataport->name);

	return 0;

unmap_bars:
	for (i = 0; i <= last_bar; i++) {
		iounmap(dataport->mem[i].service_vm_va);
	}
	pci_release_regions(dev);

disable_pci:
	pci_disable_device(dev);

free_dataport:
	kfree(dataport);

	pci_err(dev, "probing dataport failed\n");
	return -ENODEV;
}

static void sel4_pci_remove(struct pci_dev *dev)
{
	struct sel4_dataport *dataport = pci_get_drvdata(dev);
	int notify_id = -1;
	int i;

	if (!dataport)
		return;

	mutex_lock(&sel4_dataports_lock);
	if (dataport->vmm_id >= 0 && dataport->state == SEL4_DATAPORT_ACTIVE) {
		struct sel4_vmm *vmm;
		set_dataports_state(dataport->vmm_id, SEL4_DATAPORT_REMOVING);
		notify_id = dataport->vmm_id;

		vmm = sel4_vmmpool_remove(dataport->vmm_id);
		if (vmm) {
			set_dataports_state(dataport->vmm_id, SEL4_DATAPORT_REMOVED);
			sel4_pci_vmm_destroy(vmm);
			notify_id = -1;
		}
	}

	/* we can now remove dataport from the list - notify will find the
	 * state of the other dataport pair 'removing', and set it 'removed'
	 */
	list_del(&dataport->list);
	mutex_unlock(&sel4_dataports_lock);

	if (notify_id >= 0) {
		WARN_ON(sel4_notify_vmm_dying(notify_id));
	}

	pci_info(dev, "destroying %s\n", dataport->name);

	for (i = 0; i < 2; i++) {
		iounmap(dataport->mem[i].service_vm_va);
	}
	pci_release_regions(dev);
	pci_disable_device(dev);
	kfree(dataport);
}

static struct sel4_vmm *sel4_pci_vm_create(struct sel4_vm_params params)
{
	struct sel4_vmm *vmm;
	mutex_lock(&sel4_dataports_lock);
	vmm = sel4_vmmpool_get(params.id, params.ram_size);
	mutex_unlock(&sel4_dataports_lock);
	return vmm;
}

static int sel4_pci_vm_destroy(struct sel4_vmm *vmm)
{
	int rc = 0;

	mutex_lock(&sel4_dataports_lock);
	if (dataports_active(vmm->id)) {
		/* dataports still active, return to pool */
		rc = sel4_vmmpool_add(vmm);
		goto out;
	}

	/* dataports getting destroyed, destroy vmm */
	set_dataports_state(vmm->id, SEL4_DATAPORT_REMOVED);
	sel4_pci_vmm_destroy(vmm);
out:
	mutex_unlock(&sel4_dataports_lock);

	return rc;
}

static struct sel4_vm_server vm_server = {
	.create_vm = sel4_pci_vm_create,
	.destroy_vm = sel4_pci_vm_destroy,
};

static struct pci_device_id sel4_pci_ids[] = {
	{
		.vendor =       PCI_VENDOR_ID_REDHAT_QUMRANET,
		.device =       PCI_SEL4_DEVICE_ID,
		.subvendor =    PCI_ANY_ID,
		.subdevice =    PCI_ANY_ID,
	},
	{0,}
};

static struct pci_driver sel4_pci_driver = {
	.name = "sel4",
	.id_table = sel4_pci_ids,
	.probe = sel4_pci_probe,
	.remove = sel4_pci_remove,
};

static int __init sel4_pci_init(void)
{
	int rc = sel4_init(&vm_server, THIS_MODULE);
	if (rc) {
		pr_err("Failed to initialize sel4 driver\n");
		return rc;
	}

	return pci_register_driver(&sel4_pci_driver);
}
module_init(sel4_pci_init);

static void __exit sel4_pci_exit(void)
{
	pci_unregister_driver(&sel4_pci_driver);
	sel4_exit();
}
module_exit(sel4_pci_exit);

MODULE_AUTHOR("Technology Innovation Institute");
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("Module for managing seL4 guest VMs over virtual PCI");
