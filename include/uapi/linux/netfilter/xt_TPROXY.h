/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _XT_TPROXY_H
#define _XT_TPROXY_H

#include <linux/types.h>
#include <linux/netfilter.h>

/* TPROXY target is capable of marking the packet to perform
 * redirection. We can get rid of that whenever we get support for
 * mutliple targets in the same rule. */
struct xt_tproxy_target_info {
	__u32 mark_mask; //mark掩码
	__u32 mark_value; //mark值
	__be32 laddr; //重定向的IP。这里用重定向，是遵从iptables中对这个变量的说明，但实际上更像“监听IP”
	__be16 lport; //重定向的端口
};

/* 成员同上，只是laddr支持IPv6 */
struct xt_tproxy_target_info_v1 {
	__u32 mark_mask;
	__u32 mark_value;
	union nf_inet_addr laddr;
	__be16 lport;
};

#endif /* _XT_TPROXY_H */
