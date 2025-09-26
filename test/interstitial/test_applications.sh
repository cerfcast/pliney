#!/bin/env bash

# Test that
# 1. Modifies the TTL (32)
# of an IPv4 DNS query for Google.
sudo PLINEY_PIPELINE="ttl 32" LD_PRELOAD=build/libplineyi.so  nslookup google.com

# Test that
# 1. Changes the body to a DNS query for cnn.com
# of an IPv4 DNS query for Google.
sudo PLINEY_PIPELINE="body test/data/dns_cnn" LD_PRELOAD=build/libplineyi.so  nslookup google.com

# Test that
# 1. Adds HBH extension headers;
# 2. Modifies the TTL (32); and
# 3. Changes the target
# of an IPv6 DNS query for Google.
sudo PLINEY_PIPELINE="exthdr-padn hbh 4 00 => ttl 32 => target fd7a:115c:a1e0:ab12:4843:cd96:627b:e21e" LD_PRELOAD=build/libplineyi.so  nslookup google.com ::1

# Test that
# 1. Adds HBH extension headers;
# 2. Modifies the TTL (32); and
# 3. Changes the body to a DNS query for cnn.com
# of an IPv6 DNS query for Google.
sudo PLINEY_PIPELINE="exthdr-padn hbh 4 00 => ttl 32 => body test/data/dns_cnn" LD_PRELOAD=build/libplineyi.so  nslookup google.com ::1