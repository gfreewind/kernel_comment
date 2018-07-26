/*
 * Transparent proxy support for Linux/iptables
 *
 * Copyright (c) 2006-2010 BalaBit IT Ltd.
 * Author: Balazs Scheidler, Krisztian Kovacs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <net/checksum.h>
#include <net/udp.h>
#include <net/tcp.h>
#include <net/inet_sock.h>
#include <net/inet_hashtables.h>
#include <linux/inetdevice.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter_ipv4/ip_tables.h>

#include <net/netfilter/ipv4/nf_defrag_ipv4.h>

#if IS_ENABLED(CONFIG_IP6_NF_IPTABLES)
#define XT_TPROXY_HAVE_IPV6 1
#include <net/if_inet6.h>
#include <net/addrconf.h>
#include <net/inet6_hashtables.h>
#include <linux/netfilter_ipv6/ip6_tables.h>
#include <net/netfilter/ipv6/nf_defrag_ipv6.h>
#endif

#include <net/netfilter/nf_tproxy.h>
#include <linux/netfilter/xt_TPROXY.h>

/* assign a socket to the skb -- consumes sk */
static void
nf_tproxy_assign_sock(struct sk_buff *skb, struct sock *sk)
{
	skb_orphan(skb);//让skb成为孤儿，也就是与原有socket脱离关系
	skb->sk = sk;
	skb->destructor = sock_edemux;
}

static unsigned int
tproxy_tg4(struct net *net, struct sk_buff *skb, __be32 laddr, __be16 lport,
	   u_int32_t mark_mask, u_int32_t mark_value)
{
	const struct iphdr *iph = ip_hdr(skb);
	struct udphdr _hdr, *hp;
	struct sock *sk;

	/*
	获取UDP首部。因为在netfilter层，不能保证是4层首部是线性化的，所以需要使用skb_header_pointer得到首部内容。
	另外UDP首部和TCP的固定首部前4个字节，都是源端口和目的端口
	*/
	hp = skb_header_pointer(skb, ip_hdrlen(skb), sizeof(_hdr), &_hdr);
	if (hp == NULL)
		return NF_DROP;

	/* check if there's an ongoing connection on the packet
	 * addresses, this happens if the redirect already happened
	 * and the current packet belongs to an already established
	 * connection */
	sk = nf_tproxy_get_sock_v4(net, skb, iph->protocol,
				   iph->saddr, iph->daddr,
				   hp->source, hp->dest,
				   skb->dev, NF_TPROXY_LOOKUP_ESTABLISHED);//查找是否有established状态的socket。注意这里使用的是数据包真实的IP和端口

	laddr = nf_tproxy_laddr4(skb, laddr, iph->daddr);
	if (!lport)//用户没有配置监听端口，则使用数据包的目的端口
		lport = hp->dest;

	/* UDP has no TCP_TIME_WAIT state, so we never enter here */
	if (sk && sk->sk_state == TCP_TIME_WAIT)//匹配的socket是TIME_WAIT状态
		/* reopening a TIME_WAIT connection needs special handling */
		sk = nf_tproxy_handle_time_wait4(net, skb, laddr, lport, sk);
	else if (!sk)//匹配listen状态的socket
		/* no, there's no established connection, check if
		 * there's a listener on the redirected addr/port */
		sk = nf_tproxy_get_sock_v4(net, skb, iph->protocol,
					   iph->saddr, laddr,
					   hp->source, lport,
					   skb->dev, NF_TPROXY_LOOKUP_LISTENER);

	/* NOTE: assign_sock consumes our sk reference */
	if (sk && nf_tproxy_sk_is_transparent(sk)) {//找到了socket，且该socket是
		/* This should be in a separate target, but we don't do multiple
		   targets on the same rule yet */
		skb->mark = (skb->mark & ~mark_mask) ^ mark_value;//设置skb的mark值

		pr_debug("redirecting: proto %hhu %pI4:%hu -> %pI4:%hu, mark: %x\n",
			 iph->protocol, &iph->daddr, ntohs(hp->dest),
			 &laddr, ntohs(lport), skb->mark);

		nf_tproxy_assign_sock(skb, sk);//将skb交给该socket
		return NF_ACCEPT;
	}

	pr_debug("no socket, dropping: proto %hhu %pI4:%hu -> %pI4:%hu, mark: %x\n",
		 iph->protocol, &iph->saddr, ntohs(hp->source),
		 &iph->daddr, ntohs(hp->dest), skb->mark);
	return NF_DROP;
}

static unsigned int
tproxy_tg4_v0(struct sk_buff *skb, const struct xt_action_param *par)
{
	const struct xt_tproxy_target_info *tgi = par->targinfo;

	return tproxy_tg4(xt_net(par), skb, tgi->laddr, tgi->lport,
			  tgi->mark_mask, tgi->mark_value);
}

static unsigned int
tproxy_tg4_v1(struct sk_buff *skb, const struct xt_action_param *par)
{
	const struct xt_tproxy_target_info_v1 *tgi = par->targinfo;

	return tproxy_tg4(xt_net(par), skb, tgi->laddr.ip, tgi->lport,
			  tgi->mark_mask, tgi->mark_value);
}

#ifdef XT_TPROXY_HAVE_IPV6

/* IPv6的tproxy target与IPv4类似，不再重复 */
static unsigned int
tproxy_tg6_v1(struct sk_buff *skb, const struct xt_action_param *par)
{
	const struct ipv6hdr *iph = ipv6_hdr(skb);
	const struct xt_tproxy_target_info_v1 *tgi = par->targinfo;
	struct udphdr _hdr, *hp;
	struct sock *sk;
	const struct in6_addr *laddr;
	__be16 lport;
	int thoff = 0;
	int tproto;

	tproto = ipv6_find_hdr(skb, &thoff, -1, NULL, NULL);
	if (tproto < 0) {
		pr_debug("unable to find transport header in IPv6 packet, dropping\n");
		return NF_DROP;
	}

	hp = skb_header_pointer(skb, thoff, sizeof(_hdr), &_hdr);
	if (hp == NULL) {
		pr_debug("unable to grab transport header contents in IPv6 packet, dropping\n");
		return NF_DROP;
	}

	/* check if there's an ongoing connection on the packet
	 * addresses, this happens if the redirect already happened
	 * and the current packet belongs to an already established
	 * connection */
	sk = nf_tproxy_get_sock_v6(xt_net(par), skb, thoff, tproto,
				   &iph->saddr, &iph->daddr,
				   hp->source, hp->dest,
				   xt_in(par), NF_TPROXY_LOOKUP_ESTABLISHED);

	laddr = nf_tproxy_laddr6(skb, &tgi->laddr.in6, &iph->daddr);
	lport = tgi->lport ? tgi->lport : hp->dest;

	/* UDP has no TCP_TIME_WAIT state, so we never enter here */
	if (sk && sk->sk_state == TCP_TIME_WAIT) {
		const struct xt_tproxy_target_info_v1 *tgi = par->targinfo;
		/* reopening a TIME_WAIT connection needs special handling */
		sk = nf_tproxy_handle_time_wait6(skb, tproto, thoff,
					      xt_net(par),
					      &tgi->laddr.in6,
					      tgi->lport,
					      sk);
	}
	else if (!sk)
		/* no there's no established connection, check if
		 * there's a listener on the redirected addr/port */
		sk = nf_tproxy_get_sock_v6(xt_net(par), skb, thoff,
					   tproto, &iph->saddr, laddr,
					   hp->source, lport,
					   xt_in(par), NF_TPROXY_LOOKUP_LISTENER);

	/* NOTE: assign_sock consumes our sk reference */
	if (sk && nf_tproxy_sk_is_transparent(sk)) {
		/* This should be in a separate target, but we don't do multiple
		   targets on the same rule yet */
		skb->mark = (skb->mark & ~tgi->mark_mask) ^ tgi->mark_value;

		pr_debug("redirecting: proto %hhu %pI6:%hu -> %pI6:%hu, mark: %x\n",
			 tproto, &iph->saddr, ntohs(hp->source),
			 laddr, ntohs(lport), skb->mark);

		nf_tproxy_assign_sock(skb, sk);
		return NF_ACCEPT;
	}

	pr_debug("no socket, dropping: proto %hhu %pI6:%hu -> %pI6:%hu, mark: %x\n",
		 tproto, &iph->saddr, ntohs(hp->source),
		 &iph->daddr, ntohs(hp->dest), skb->mark);

	return NF_DROP;
}

static int tproxy_tg6_check(const struct xt_tgchk_param *par)
{
	const struct ip6t_ip6 *i = par->entryinfo;
	int err;

	err = nf_defrag_ipv6_enable(par->net);
	if (err)
		return err;

	if ((i->proto == IPPROTO_TCP || i->proto == IPPROTO_UDP) &&
	    !(i->invflags & IP6T_INV_PROTO))
		return 0;

	pr_info_ratelimited("Can be used only with -p tcp or -p udp\n");
	return -EINVAL;
}
#endif

static int tproxy_tg4_check(const struct xt_tgchk_param *par)
{
	const struct ipt_ip *i = par->entryinfo;
	int err;

	err = nf_defrag_ipv4_enable(par->net);//启用defrag即分片重组（注意，这里的分片重组是netfilter的一个hook功能）
	if (err)
		return err;

	if ((i->proto == IPPROTO_TCP || i->proto == IPPROTO_UDP)
	    && !(i->invflags & IPT_INV_PROTO))//tproxy只能应用在TCP和UDP协议上
		return 0;

	pr_info_ratelimited("Can be used only with -p tcp or -p udp\n");
	return -EINVAL;
}

/*
使用示例:
#将目的端口是80的TCP流量，匹配到本地50080的透明模式的socket
iptables -t mangle -A PREROUTING -p tcp --dport 80 -j TPROXY \
  --tproxy-mark 0x1/0x1 --on-port 50080

#增加策略路由规则
#mark值为1的查询路由表100
ip rule add fwmark 1 lookup 100
#配置路由规则，所有目的IP均被当作发给本地的
ip route add local 0.0.0.0/0 dev lo table 100

*/
static struct xt_target tproxy_tg_reg[] __read_mostly = {
	{
		.name		= "TPROXY",
		.family		= NFPROTO_IPV4,
		.table		= "mangle",
		.target		= tproxy_tg4_v0,
		.revision	= 0,
		.targetsize	= sizeof(struct xt_tproxy_target_info),
		.checkentry	= tproxy_tg4_check,
		.hooks		= 1 << NF_INET_PRE_ROUTING,
		.me		= THIS_MODULE,
	},
	{
		.name		= "TPROXY",
		.family		= NFPROTO_IPV4,
		.table		= "mangle",
		.target		= tproxy_tg4_v1,
		.revision	= 1,
		.targetsize	= sizeof(struct xt_tproxy_target_info_v1),
		.checkentry	= tproxy_tg4_check,
		.hooks		= 1 << NF_INET_PRE_ROUTING,
		.me		= THIS_MODULE,
	},
#ifdef XT_TPROXY_HAVE_IPV6
	{
		.name		= "TPROXY",
		.family		= NFPROTO_IPV6,
		.table		= "mangle",
		.target		= tproxy_tg6_v1,
		.revision	= 1,
		.targetsize	= sizeof(struct xt_tproxy_target_info_v1),
		.checkentry	= tproxy_tg6_check,
		.hooks		= 1 << NF_INET_PRE_ROUTING,
		.me		= THIS_MODULE,
	},
#endif

};

static int __init tproxy_tg_init(void)
{
	return xt_register_targets(tproxy_tg_reg, ARRAY_SIZE(tproxy_tg_reg));//注册tproxy target
}

static void __exit tproxy_tg_exit(void)
{
	xt_unregister_targets(tproxy_tg_reg, ARRAY_SIZE(tproxy_tg_reg));//卸载tproxy target
}

module_init(tproxy_tg_init);
module_exit(tproxy_tg_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Balazs Scheidler, Krisztian Kovacs");
MODULE_DESCRIPTION("Netfilter transparent proxy (TPROXY) target module.");
MODULE_ALIAS("ipt_TPROXY");
MODULE_ALIAS("ip6t_TPROXY");
