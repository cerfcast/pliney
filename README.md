## Pliney - A Framework For Writing Pipelines To Generate IP Packets

Anyone who's ever written a piece of network software knows that there is always that _one_ type of
packet they need to generate to test their code. Maybe that packet has a certain contents. Maybe it
has certain values in the header. Who knows? 

What we do know is that it should be much easier to generate a packet with _that_ format so that we
can test our software!

That's where Pliney can help!

Inspired by the ease with which multimedia manipulation can be done on command line using the `gst-launch-1.0`
command from gstreamer, pliney makes it possible to write _pipelines_ that generate IP packets by specifying
pipelines on the command line where each _component_ manipulates some characteristic of the IP packet(s) that
are generated.

Want an IPv6 UDP packet sent to `fd7a:115c:a1e0:ab12:4843:cd96:627b:e21e` (port `8081`) with a hop-by-hop extension
header that contains 6 bytes of padding and the contents that come from the first 50 bytes of `my_data.bin`? Try _this_:

```bash
$ pliney target fd7a:115c:a1e0:ab12:4843:cd96:627b:e21e 8081  =\> type dgram =\> body my_data.bin 50 =\> exthdr-padn hbh 6
```

### Test Cases

```console
$ ./build/packetline sender arg1 arg2 =\> sender2 arg21 arg22 arg23  
```

