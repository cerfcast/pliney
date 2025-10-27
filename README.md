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

Pliney pipelines can also be used to modify packets send by other applications!

> Note: Support for this use case is still very nascent.

By loading the _Pliney Interstitial_ library and setting the `PLINEY_PIPELINE` environment variable, packets sent by applications
using the `sendto` and `sendmsg` system call will be modified according to the semantics of the pipeline specified.

For example, if you want to set the TTL to 12 on all DNS packets sent by `nslookup` to resolve `cnn.com`, you could

```bash
$ PLINEY_PIPELINE="ttl 12" LD_PRELOAD=/path/to/libplineyi.so nslookup cnn.com
```

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

#### Interstitial

More coming soon!

**Warnings**:
1. When retargeting packets (i.e., a pliney pipeline uses the `target` plugin), if the connection on which packets are being retargeted was created on a socket
   that cannot route to the specified new target, then those packets will not be transmitted.

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

#### Interstitial

##### Redirect nslookup to 8.8.8.8

```bash
$ PLINEY_PIPELINE="target 8.8.8.8 53" LD_PRELOAD=build/libplineyi.so  nslookup cnn.com 1.1.1.1
```

##### Rewrite Contents of ICMP (And Add TOS/Diffserv)

```bash
$ PLINEY_PIPELINE="diffserv af42 => cong ce => body test/data/icmp.bin" LD_PRELOAD=build/libplineyi.so ping 8.8.8.8 -c 4 -w 1
```

##### Rewrite nslookup from Google to CNN

```bash
$ PLINEY_PIPELINE="body test/data/dns_cnn" LD_PRELOAD=build/libplineyi.so  nslookup google.com
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

[^padn-length]: "Linux source code (v6.16.9) - Bootlin Elixir Cross Referencer" Available: https://elixir.bootlin.com/linux/v6.16.9/source/net/ipv6/exthdrs.c#L150. [Accessed: Sep. 26, 2025]
 
[^padn-zeros]: "Linux source code (v6.16.9) - Bootlin Elixir Cross Referencer" Available: https://elixir.bootlin.com/linux/v6.16.9/source/net/ipv6/exthdrs.c#L159. [Accessed: Sep. 26, 2025]


