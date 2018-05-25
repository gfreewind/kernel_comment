/*
 * 'raw' table, which is the very first hooked in at PRE_ROUTING and LOCAL_OUT .
 *
 * Copyright (C) 2003 Jozsef Kadlecsik <kadlec@blackhole.kfki.hu>
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/module.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/slab.h>
#include <net/ip.h>

#define RAW_VALID_HOOKS ((1 << NF_INET_PRE_ROUTING) | (1 << NF_INET_LOCAL_OUT))

static int __net_init iptable_raw_table_init(struct net *net);

static bool raw_before_defrag __read_mostly;
MODULE_PARM_DESC(raw_before_defrag, "Enable raw table before defrag");
module_param(raw_before_defrag, bool, 0000);

/*
raw表是netfilter不太常用的表，其优先级非常高。常用于target NOTRACK
这里有2个raw表的定义，一个是在defrag（处理分片）之前，一个是在之后。
由加载这个模块时的参数raw_before_defrag而定，默认是在defrag之后。
*/
static const struct xt_table packet_raw = {
	.name = "raw",
	.valid_hooks =  RAW_VALID_HOOKS,
	.me = THIS_MODULE,
	.af = NFPROTO_IPV4,
	.priority = NF_IP_PRI_RAW,
	.table_init = iptable_raw_table_init,
};

static const struct xt_table packet_raw_before_defrag = {
	.name = "raw",
	.valid_hooks =  RAW_VALID_HOOKS,
	.me = THIS_MODULE,
	.af = NFPROTO_IPV4,
	.priority = NF_IP_PRI_RAW_BEFORE_DEFRAG,
	.table_init = iptable_raw_table_init,
};

/* The work comes in here from netfilter.c. */
static unsigned int
iptable_raw_hook(void *priv, struct sk_buff *skb,
		 const struct nf_hook_state *state)
{
	// 这个hook函数很简单，就是执行table中的规则
	return ipt_do_table(skb, state, state->net->ipv4.iptable_raw);
}

static struct nf_hook_ops *rawtable_ops __read_mostly;

static int __net_init iptable_raw_table_init(struct net *net)
{
	struct ipt_replace *repl;
	const struct xt_table *table = &packet_raw;
	int ret;

	if (raw_before_defrag)
		table = &packet_raw_before_defrag;

	if (net->ipv4.iptable_raw)
		return 0;

	/*
	repl的类型struct ipt_replace是iptables用户态针对一个表的规则的集合。
	这里初始化这个规则结构
	*/
	repl = ipt_alloc_initial_table(table);
	if (repl == NULL)
		return -ENOMEM;
	ret = ipt_register_table(net, table, repl, rawtable_ops,
				 &net->ipv4.iptable_raw); // 注册表，同时会把repl转换成dataplane时的结构
	kfree(repl); // repl已经无用了（前面已经转换成了dataplane的结构），可以安全释放。
	return ret;
}

static void __net_exit iptable_raw_net_exit(struct net *net)
{
	if (!net->ipv4.iptable_raw)
		return;
	ipt_unregister_table(net, net->ipv4.iptable_raw, rawtable_ops);
	net->ipv4.iptable_raw = NULL;
}

static struct pernet_operations iptable_raw_net_ops = {
	.exit = iptable_raw_net_exit,
};

static int __init iptable_raw_init(void)
{
	int ret;
	const struct xt_table *table = &packet_raw;

	if (raw_before_defrag) {
		table = &packet_raw_before_defrag;

		pr_info("Enabling raw table before defrag\n");
	}

	/*
	为每个table需要需要的hook创建了nf_hook_ops。对于raw表来说，就是prerouting和localout。
	这里的rawtable_ops会在注册raw表时使用。
	*/
	rawtable_ops = xt_hook_ops_alloc(table, iptable_raw_hook);
	if (IS_ERR(rawtable_ops))
		return PTR_ERR(rawtable_ops);

	ret = register_pernet_subsys(&iptable_raw_net_ops);
	if (ret < 0) {
		kfree(rawtable_ops);
		return ret;
	}

	ret = iptable_raw_table_init(&init_net);
	if (ret) {
		unregister_pernet_subsys(&iptable_raw_net_ops);
		kfree(rawtable_ops);
	}

	return ret;
}

static void __exit iptable_raw_fini(void)
{
	unregister_pernet_subsys(&iptable_raw_net_ops);
	kfree(rawtable_ops);
}

module_init(iptable_raw_init);
module_exit(iptable_raw_fini);
MODULE_LICENSE("GPL");
