// SPDX-License-Identifier: GPL-2.0-only

/*
 *  drivers/net/bpfnic-helper.c
 *
 * Helper allowing userspace to work with kernel bridge offloads
 *
 *  Copyright (C) 2023 Red Hat Inc
 *  Copyright (C) 2023 Cambridge Greys Ltd
 *
 * Author: Anton Ivanov
 *
 */

#include <linux/netdevice.h>
#include <linux/slab.h>
#include <net/switchdev.h>
#include <linux/module.h>
#include <linux/mod_devicetable.h>
#include <linux/filter.h>
#include <linux/ptr_ring.h>
#include <linux/bpf.h>
#include <linux/namei.h>
#include <linux/kthread.h>
#include <linux/sched.h>
#include <linux/delay.h>

#include "bpfnic_shared.h"

#define DRV_NAME	"bpfnic-ng"
#define DRV_VERSION	"0.1"

/* Modus Operandi
 * The helper receives switchdev notifiers, builds ringbuf
 * entries and pushes them to userspace.
 * Userspace makes a decision - to offload or not to "offload",
 * adds relevant entries to the bpf maps controlling the "offload".
*/

static bool init_done = false;

static char *to_user_path = "";
static struct bpf_map *to_user;

static char *from_user_path = "";
static struct bpf_map *from_user;

static bool exiting = false;

static DECLARE_WAIT_QUEUE_HEAD(ringbuf_wait);

static struct task_struct *ringbuf_task;

static void build_ringbuf_entry(struct bpfnic_fdb_entry *entry,
							struct switchdev_notifier_fdb_info *fdb_info, int event)
{
	entry->ifindex = fdb_info->info.dev->ifindex;
	ether_addr_copy((u8 *) &entry->addr, fdb_info->addr);
	entry->vid = fdb_info->vid;
	entry->added_by_user = fdb_info->added_by_user;
	entry->offloaded = fdb_info->offloaded;
	entry->event = event;
}

static int bpfnic_switchdev_event(struct notifier_block *unused,
				  unsigned long event, void *ptr)
{
	struct switchdev_notifier_fdb_info *fdb_info = ptr;
	struct bpfnic_fdb_entry *fdb_entry;

	switch (event) {
	case SWITCHDEV_FDB_ADD_TO_DEVICE:
	case SWITCHDEV_FDB_DEL_TO_DEVICE:
		if (to_user) {
			fdb_entry = _bpf_ringbuf_reserve(to_user, sizeof(struct bpfnic_fdb_entry), 0);
			if (fdb_entry) {
				build_ringbuf_entry(fdb_entry, fdb_info, event);
				_bpf_ringbuf_commit(fdb_entry, 0);
			} else
				return NOTIFY_BAD;
		}
		break;
	default:
		return NOTIFY_DONE;
	}
	return NOTIFY_DONE;
}

static int emit_switchdev_notification(struct bpfnic_fdb_entry *entry)
{
	struct net_device *dev;
	struct switchdev_notifier_fdb_info fdb_info = {};

	ether_addr_copy((u8*) &fdb_info.addr, (u8*) &entry->addr);
	dev = dev_get_by_index(&init_net, entry->ifindex);
	fdb_info.info.dev = dev;
	fdb_info.vid = entry->vid;
	fdb_info.added_by_user = entry->added_by_user;
	fdb_info.offloaded = entry->offloaded;
	printk(KERN_INFO "event: %i device: %i offloaded: %i\n", entry->event, entry->ifindex, entry->offloaded);
	return call_switchdev_notifiers(entry->event, dev, &fdb_info.info, NULL);
}

static struct notifier_block bpfnic_switchdev_notifier = {
	.notifier_call = bpfnic_switchdev_event,
};

static int ringbuf_thread(void *unused)
{
	struct bpfnic_fdb_entry *entry;
	u64 size;

	/* Grab one more ref to map so it is not deleted under our feet. */
	bpf_map_inc(from_user);
	while (!exiting) {
        msleep_interruptible(1);
		int count = 0;
		while (!exiting) {
			entry = bpf_ringbuf_fetch_next(from_user, &size);
			if (!entry)
				break;
			emit_switchdev_notification(entry);
			if (count++ > 10) {
				printk(KERN_ERR "too many notifications\n");
				schedule();
			}
		}
	}
	bpf_map_put(from_user);
	return 0; 
}

static void __bpfnic_helper_exit(void);

static __init int bpfnic_helper_init(void)
{
	int ret;

	if ((strlen(to_user_path) == 0) || (strlen(from_user_path) == 0))
		return -ENODEV;

	to_user = bpf_map_get_path(to_user_path, FMODE_READ | FMODE_WRITE);
	from_user = bpf_map_get_path(to_user_path, FMODE_READ | FMODE_WRITE);

	if (IS_ERR(to_user)) {
		printk(KERN_ERR "Failed to get bpfmap, ERR %ld", PTR_ERR(to_user));
		return PTR_ERR(to_user);
	}
	if (IS_ERR(from_user)) {
		printk(KERN_ERR "Failed to get bpfmap, ERR %ld", PTR_ERR(from_user));
		__bpfnic_helper_exit();
		return PTR_ERR(from_user);
	}

	ret = register_switchdev_notifier(&bpfnic_switchdev_notifier);
	if (ret) {
		__bpfnic_helper_exit();
		printk(KERN_ERR "bpfnic - failed to register switchdev notifier\n");
	} else {
		init_done = true;
	}

	ringbuf_task = kthread_run(ringbuf_thread, NULL, "bpfnic-helper");

	if (IS_ERR(ringbuf_task)) {
		printk(KERN_ERR "Failed to run helper thread, ERR %ld", PTR_ERR(from_user));
		__bpfnic_helper_exit();
		return PTR_ERR(ringbuf_task);
	}
	
	return ret;
}

static void __bpfnic_helper_exit(void)
{
	exiting = true;
	wmb();
	if (init_done) {
		unregister_switchdev_notifier(&bpfnic_switchdev_notifier);
		init_done = false;
	}
	if (to_user && (!IS_ERR(to_user)))
		bpf_map_put(to_user);
	if (from_user && (!IS_ERR(from_user))) {
		from_user->ops->map_lookup_elem(NULL, NULL);
		bpf_map_put(from_user);
	}
}

static __exit void bpfnic_helper_exit(void)
{
	__bpfnic_helper_exit();
}

module_init(bpfnic_helper_init);
module_exit(bpfnic_helper_exit);
module_param(to_user_path, charp, S_IRUSR); 
module_param(from_user_path, charp, S_IRUSR); 


MODULE_VERSION("0.1.0");
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Anton R. Ivanov");
MODULE_DESCRIPTION("BPF helper for skb path");
