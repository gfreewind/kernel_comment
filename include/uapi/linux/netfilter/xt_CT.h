/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _XT_CT_H
#define _XT_CT_H

#include <linux/types.h>

enum {
	XT_CT_NOTRACK		= 1 << 0,//表示不进行连接跟踪
	XT_CT_NOTRACK_ALIAS	= 1 << 1,//表示notrack的别名。为了兼容NOTRACK target。用CT取代了NOTRACK
	XT_CT_ZONE_DIR_ORIG	= 1 << 2,//表示original方向的zone
	XT_CT_ZONE_DIR_REPL	= 1 << 3,//表示reply方向的zone
	XT_CT_ZONE_MARK		= 1 << 4,//表示两个方向的zone

	XT_CT_MASK		= XT_CT_NOTRACK | XT_CT_NOTRACK_ALIAS |
				  XT_CT_ZONE_DIR_ORIG | XT_CT_ZONE_DIR_REPL |
				  XT_CT_ZONE_MARK,
};

struct xt_ct_target_info {
	__u16 flags;
	__u16 zone;//zone的值
	__u32 ct_events;//连接事件
	__u32 exp_events;//expect事件
	char helper[16];//helper名字

	/* Used internally by the kernel */
	struct nf_conn	*ct __attribute__((aligned(8)));
};

struct xt_ct_target_info_v1 {
	__u16 flags;
	__u16 zone;//zone的值
	__u32 ct_events;//连接事件
	__u32 exp_events;//expect事件
	char helper[16];//helper名字
	char timeout[32];

	/* Used internally by the kernel */
	struct nf_conn	*ct __attribute__((aligned(8)));
};

#endif /* _XT_CT_H */
