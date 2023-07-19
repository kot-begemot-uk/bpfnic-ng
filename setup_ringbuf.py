#!/usr/bin/python3


'''BPF Map ringbuf kernel module demo
'''

# pybpfmap, Copyright (c) 2023 RedHat Inc
# pybpfmap, Copyright (c) 2023 Cambridge Greys Ltd

# This source code is licensed under both the BSD-style license (found in the
# LICENSE file in the root directory of this source tree) and the GPLv2 (found
# in the COPYING file in the root directory of this source tree).
# You may select, at your option, one of the above-listed licenses.


from pybpfmap.bpfrecord import BPFMap
from pybpfmap.map_types import BPF_MAP_TYPE_RINGBUF, BPF_MAP_TYPE_USER_RINGBUF

from os import unlink, chmod
import sys
import time
from struct import Struct, calcsize

FROM_K="/sys/fs/bpf/test_ringbuf_from_k"
TO_K="/sys/fs/bpf/test_ringbuf_to_k"

#/* definition of a sample sent to user-space from BPF program */
#struct event {
#	int pid;
#	char comm[TASK_COMM_LEN];
#	char filename[MAX_FILENAME_LEN];
#};

PARSER_DEF = [("ifindex", "I"), ("addr",["B","B","B","B","B","B"]), ("added_by_user","B"), ("offloaded", "B"), ("vid", "H"), ("event", "H")]

def setup_ringbuf(arg, map_type):
    '''Set up a ringbuff for the kernel switchdev notifications'''
    m = BPFMap(
            -1,
            map_type,
            "rb".encode('ascii'),
            0,
            0,
            256 * 1024,
            create=True)
    m.pin_map(arg)
    m.generate_parsers(None, PARSER_DEF)
    return m

def print_mac(arg):
    ret = []
    for addr_byte in arg:
        ret.append("{:02x}".format(addr_byte))
    return ":".join(ret)
        


def get_events(inmap, outmap):
    events = inmap.fetch_next(want_parsed=True)
    print("Have {} events".format(len(events)))
    for event in events:
        event["print_addr"] = print_mac(event["addr"])
        print("{}".format(event))
        event["offloaded"] = 0
        outmap.submit(event)
        

inmap = setup_ringbuf(FROM_K, BPF_MAP_TYPE_RINGBUF)
outmap = setup_ringbuf(TO_K, BPF_MAP_TYPE_USER_RINGBUF)

while True:
    time.sleep(1)
    get_events(inmap, outmap)
