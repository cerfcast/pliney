## Pliney - A Framework For Writing Pipelines To Generate IP Packets

Anyone who's ever written a piece of network software knows that there is always that _one_ type of
packet they need to generate to test their code. Maybe that packet has a certain contents. Maybe it
has certain values in the header. Who knows?

What we do know is that it should be much easier to generate a packet with _that_ format so that we
can test our software!

That's where Pliney can help!

Inspired by the ease with which multimedia manipulation can be done on command line using the
[`gst-launch-1.0`](https://gstreamer.freedesktop.org/documentation/tutorials/basic/gstreamer-tools.html?gi-language=c)
command from [gstreamer](https://gstreamer.freedesktop.org/), pliney makes it possible to write _pipelines_ that
generate IP packets by specifying pipelines on the command line where each _component_ manipulates some characteristic
of the IP packet(s) that are generated.

Want an IPv6 UDP packet sent to `fd7a:115c:a1e0:ab12:4843:cd96:627b:e21e` (port `8081`) with a hop-by-hop extension
header that contains 6 bytes of padding and the contents that come from the first 50 bytes of `my_data.bin`? Try _this_:

```bash
$ pliney -type dgram \!\> target fd7a:115c:a1e0:ab12:4843:cd96:627b:e21e 8081 =\> body my_data.bin 50 =\> exthdr-padn hbh 6
```

**But There's More**

Pliney pipelines can also be used to modify packets sent by other applications because it can generate XDP!

> Note: Support for this use case is still very nascent and documentation is coming soon.

### Plugins Available

| Plugin Name | Purpose |
| -- | -- |
| diffserv | Set DSCP. |
| cong | Set ECN. |
| ttl | Set TTL/hoplimit. |
| exthdr-padn | Set PadN TLVs in hop-by-hop or destination option IPv6 extension headers. |
| body | Set the contents of a packet from the contents of a file. |
| target | Set the target of a packet. |
| source | Set the source of a packet. |
| log | Log the contents of the packet (in libpcap format) to a file. |
| raw | Log the contents of the body of the packet (as raw bytes) to a file. |
| gre | Tunnel the packet (in a GRE tunnel) to another host. (Currently supports only delivery through IPv4 and encapsulation of IP packets) |

**More documentation (and more plugins!) coming soon.**

### Using

#### Cli

More coming soon!

#### XDP

More coming soon!

### Test Cases

#### Cli

##### Send Data Over IPv6 And Include PadN Extension Headers

```bash
$ path/to/pliney -type dgram \!\> target fd7a:115c:a1e0:ab12:4843:cd96:627b:e21e 8081 =\> body test/data/test_data.bin 50 =\> exthdr-padn hbh 4 fe =\> exthdr-padn hbh 6 ef =\> exthdr-padn dst 4 ab =\> source fd7a:115c:a1e0::5fa2:3b13
```

##### Send Data to Google DNS

```bash
$ path/to/pliney -type dgram \!\> body ./test/data/test_data.bin 50 =\> target 8.8.8.8 53
```

##### Attempt To Open HTTP Connection to cnn.com

```bash
$ path/to/pliney \!\> body ./test/data/http_get =\> target 151.101.3.5 80
```

```bash
$ path/to/pliney \!\> body ./test/data/http_get =\> target www.cnn.com 80
```

##### DNS Query For cnn.com

```bash
$ path/to/pliney \!\> body ./test/data/dns_cnn =\> target 127.0.0.53 53
```

#### XDP

More detailed information coming soon!

##### Generating

After generating the xdp, run

```console
$ make -f Makefile.xdp
```

To _load_, run

```console
$ make -f Makefile.xdp load
```

To _unload_, run

```console
$ make -f Makefile.xdp unload
```

### Warnings/Notes

#### Linux Behavior For IPv6 Extension Headers

1. PadN TLV length must be less than 7 bytes in length.[^padn-length]
2. PadN TLV bodies can only contain 0s.[^padn-zeros]

### XDP Idea Notes

1. `refl.sh` and `refl-down.sh` can be `source`'d to configure development environment.
2. Run the rewriter in the namespace.
3. The rewriter creates a TAP interface -- that must be `up`'d:
```console
$ ip link set tapst0 up
```
4. Then, the tap interface needs to have the same ll address as the IP interface. (Use `ip link set address` to do that.)
5. The "kernel side" makes sure that all Ethernet packets pass untouched. Only IP packets are passed to userspace. Note: That means that the "program must be loaded" (c.f. a ["default libbpf program"](https://doc.dpdk.org/guides/howto/af_xdp_dp.html)).

Questions left to answer: 
1. How to make the setup/use "easy" for a user?
2. Can it be done on egress?

TODOs:
1. Use netlink to `up` the TAP interface.

#### References

- [Original Idea for Putting Component Into Namespace](https://www.josehu.com/technical/2023/10/28/emulating-network-env.html)
- [TUN/TAP Resource](https://backreference.org/2010/03/26/tuntap-interface-tutorial/)
- [TUN/TAP Resource -- A Good Reminder That Interfaces Need to be `up`'d](https://john-millikin.com/creating-tun-tap-interfaces-in-linux)

[^padn-length]: "Linux source code (v6.16.9) - Bootlin Elixir Cross Referencer" Available: https://elixir.bootlin.com/linux/v6.16.9/source/net/ipv6/exthdrs.c#L150. [Accessed: Sep. 26, 2025]
 
[^padn-zeros]: "Linux source code (v6.16.9) - Bootlin Elixir Cross Referencer" Available: https://elixir.bootlin.com/linux/v6.16.9/source/net/ipv6/exthdrs.c#L159. [Accessed: Sep. 26, 2025]


