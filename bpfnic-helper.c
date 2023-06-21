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
			fdb_entry = bpf_ringbuf_reserve_kernel(to_user, sizeof(struct bpfnic_fdb_entry), 0);
			if (fdb_entry) {
				build_ringbuf_entry(fdb_entry, fdb_info, event);
				bpf_ringbuf_commit_kernel(fdb_entry, 0);
			} else
				return NOTIFY_BAD;
		}
		break;
	default:
		return NOTIFY_DONE;
	}
	return NOTIFY_DONE;
}

static struct notifier_block bpfnic_switchdev_notifier = {
	.notifier_call = bpfnic_switchdev_event,
};

static __init int bpfnic_helper_init(void)
{
	int ret;

	if (strlen(to_user_path) == 0)
		return -ENODEV;

	to_user = bpf_map_get_path(to_user_path, FMODE_READ | FMODE_WRITE);

	if (IS_ERR(to_user)) {
		printk(KERN_ERR "Failed to get bpfmap, ERR %ld", PTR_ERR(to_user));
		return PTR_ERR(to_user);
	} else {
		printk(KERN_INFO "MAP OK");
	}

	ret = register_switchdev_notifier(&bpfnic_switchdev_notifier);
	if (ret) {
		bpf_map_put(to_user);
		/* bpf_map_put(from_user); */
		printk(KERN_ERR "bpfnic - failed to register switchdev notifier\n");
	} else {
		init_done = true;
	}
	return ret;
}


static __exit void bpfnic_helper_exit(void)
{
	if (init_done) {
		unregister_switchdev_notifier(&bpfnic_switchdev_notifier);
		init_done = false;
	}
	if (to_user)
		bpf_map_put(to_user);
}

module_init(bpfnic_helper_init);
module_exit(bpfnic_helper_exit);
module_param(to_user_path, charp, S_IRUSR); 


MODULE_VERSION("0.1.0");
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Anton R. Ivanov");
MODULE_DESCRIPTION("BPF helper for skb path");
