# bpfnic-ng
The main goal of the project is to implement a "Smart" NIC on top of veth (or a dedicated driver derived from veth) in skb mode using eBPF as firmware. This should
allow testing and investigating various smartnic concepts without the need to have dedicated hardware.

The project also serves as a demonstrator for the general usefulness of various infrastructure designed for BPF. For example, using ringbuf as a generic
kernel-to-userspace API.

# build

The example relies on the pybpfmap python package available at: https://github.com/kot-begemot-uk/pybpfmap

1. Build pybpfmap
1. Patch a reasonably recent kernel using the export-ringbuf.patch. The patch is versus 6.1.32. It should apply to most recent kernels.
1. Build the kernel
1. Build the code as an out-of-tree module

# run

1. Run the setup\_ringbuf.py script to set up a pinned ringbuf for the kernel module
1. Insert the kernel module specifying the pinned path as an argument
1. Observe the notifications on the Switchdev chain consumed by the module (for now - we just observe).
