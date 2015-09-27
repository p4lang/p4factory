This target illustartes as simply as possible how to "send packets to CPU"
(e.g. to a controller).

The P4 program does the following:
- incoming packets are mirrored to the CPU port using the `clone_ingress_pkt_to_egress` action primitive
- packets mirrored to CPU are encapsulated with a custom `cpu_header` which includes 2 fields: `device` (1 byte, set to `0`) and `reason` (one byte, set to `0xab`)
- the original packet is dropped in the egress pipeline

Take a look at `p4src/copy_to_cpu.p4`. The program is very short and should be easy to understand.
You will notice that we use a mirror session id of `250` in the program. This number is not relevant in itself, but needs to be consistent between the P4 program and the runtime application.

You can compile the P4 program with `make bm` as always.

We provide a small demo to let you test the program. It consists of the following scripts:
- add_demo_entries.py: our runtime application, it configures the data plane. Note that we hardcode port 3 as our CPU port, which means all mirrored packets will show up on this port.
- receive.py: sniff packets on port 3 (veth6) and print a hexdump of them
- send_one.py: send one simple IPv4 packet on port 0 (veth0)

To run the demo:
- start the switch: `sudo ./behavioral-model`
- configure the tables and the mirroring session: `python add_demo_entries.py`
- start the CPU port listener: `sudo python receive.py`
- send packets with `sudo python send_one.py`. Every time you send one packet, it should be displayed by the listener, encapsulated with our CPU header.

This is a very simple example obviously. Feel free to build upon it. For example, instead of dropping the original packet, you could try to broadcast it out of every non-ingress port to have a working L2 switch. You could also build a L2 controller which receives CPU packets and modifies tables appropriately.
