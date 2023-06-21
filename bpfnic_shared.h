/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2002 2007 Jeff Dike (jdike@{addtoit,linux.intel}.com)
 */

#ifndef __BPFNIC_SHARED_H
#define __BPFNIC_SHARED_H

struct bpfnic_fdb_entry {
	u32 ifindex;
	u8 addr[6];
	/* these two flags effectively pad the address to a 64 bit boundary */
	u8 added_by_user;
	u8 offloaded;
	u16 vid;
    u16 event;
};

#endif
