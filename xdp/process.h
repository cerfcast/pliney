#ifndef __PROCESS_H
#define __PROCESS_H

#define TC_ACT_OK 0
#define TC_ACT_DROP 2

//#define TESTING

#define CHECK_BREADTH(st, end) CHECK_BREADTH_MULTIPLE(st, 1, end)
#define CHECK_BREADTH_MULTIPLE(st, mult, end) if (((void *)(st + mult)) > end)

__attribute__((always_inline)) int
pliney_process_v6(struct ip6_hdr *ip6, int good_result, int bad_result);

__attribute__((always_inline)) int
pliney_process_v4(struct iphdr *ip, int good_result, int bad_result);

#endif