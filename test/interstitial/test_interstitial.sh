#!/bin/env bash

# Baseline tests.
sudo build/test/interstitial/interstitial_test asdf
sudo build/test/interstitial/interstitial_test

# IPv6 test that
# 1. Adds a HBH extension header.
# 2. Sets the TTL to 32.
# 3. Redirects the packet to the localhost.
# 4. Completely replaces user-application packet with a DNS Query.
sudo PLINEY_PIPELINE="exthdr-padn hbh 4 de => ttl 32 => target ::1 => body test/data/dns_cnn" LD_PRELOAD=build/libplineyi.so  build/test/interstitial/interstitial_test asdf

# IPv4 test that
# 1. Sets the TTL to 32.
# 2. Redirects the packet to 12.12.12.12.
# 3. Completely replaces user-applications packet with a DNS Query.
sudo PLINEY_PIPELINE="ttl 32 => target 12.12.12.12 => body test/data/dns_cnn" LD_PRELOAD=build/libplineyi.so  build/test/interstitial/interstitial_test 


# IPv6 test that
# 1. Adds a HBH extension header.
# 2. Sets the TTL to 32.
# 3. Redirects the packet.
sudo PLINEY_PIPELINE="exthdr-padn hbh 4 de => ttl 32 => target fd7a:115c:a1e0:ab12:4843:cd96:627b:e21e" LD_PRELOAD=build/libplineyi.so  build/test/interstitial/interstitial_test asdf
