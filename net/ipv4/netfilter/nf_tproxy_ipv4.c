/*
 * Copyright (C) 2007-2008 BalaBit IT Ltd.
 * Author: Krisztian Kovacs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#include <net/netfilter/nf_tproxy.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <net/inet_sock.h>
#include <linux/ip.h>
#include <net/checksum.h>
#include <net/udp.h>
#include <net/tcp.h>
#include <linux/inetdevice.h>

struct sock *
nf_tproxy_handle_time_wait4(struct net *net, struct sk_buff *skb,
			 __be32 laddr, __be16 lport, struct sock *sk)
{
	const struct iphdr *iph = ip_hdr(skb);
	struct tcphdr _hdr, *hp;

	hp = skb_header_pointer(skb, ip_hdrlen(skb), sizeof(_hdr), &_hdr);
	if (hp == NULL) {//获取TCP首部失败，就释放掉socket
		inet_twsk_put(inet_twsk(sk));
		return NULL;
	}

	if (hp->syn && !hp->rst && !hp->ack && !hp->fin) {//如果是syn包，那就尝试匹配listen状态的socket
		/* SYN to a TIME_WAIT socket, we'd rather redirect it
		 * to a listener socket if there's one */
		struct sock *sk2;

		sk2 = nf_tproxy_get_sock_v4(net, skb, iph->protocol,
					    iph->saddr, laddr ? laddr : iph->daddr,
					    hp->source, lport ? lport : hp->dest,
					    skb->dev, NF_TPROXY_LOOKUP_LISTENER);
		if (sk2) {
			inet_twsk_deschedule_put(inet_twsk(sk));//如果找到listen状态的socket，可以尽快杀掉timewait状态的socket
			sk = sk2;
		}
	}

	return sk;
}
EXPORT_SYMBOL_GPL(nf_tproxy_handle_time_wait4);

__be32 nf_tproxy_laddr4(struct sk_buff *skb, __be32 user_laddr, __be32 daddr)//获得监听地址
{
	struct in_device *indev;
	__be32 laddr;

	if (user_laddr)//用户配置了地址，就使用指定地址
		return user_laddr;

	/*
	用户没有配置地址，就使用接收网卡的primary ip。
	*/
	laddr = 0;
	indev = __in_dev_get_rcu(skb->dev);
	for_primary_ifa(indev) {
		laddr = ifa->ifa_local;
		break;
	} endfor_ifa(indev);

	return laddr ? laddr : daddr;//没有找到的话，就使用数据包的目的地址
}
EXPORT_SYMBOL_GPL(nf_tproxy_laddr4);

struct sock *
nf_tproxy_get_sock_v4(struct net *net, struct sk_buff *skb,
		      const u8 protocol,
		      const __be32 saddr, const __be32 daddr,
		      const __be16 sport, const __be16 dport,
		      const struct net_device *in,
		      const enum nf_tproxy_lookup_t lookup_type)
{
	struct sock *sk;

	switch (protocol) {
	case IPPROTO_TCP: {
		struct tcphdr _hdr, *hp;

		hp = skb_header_pointer(skb, ip_hdrlen(skb),//得到TCP首部
					sizeof(struct tcphdr), &_hdr);
		if (hp == NULL)
			return NULL;

		switch (lookup_type) {
		case NF_TPROXY_LOOKUP_LISTENER:
			sk = inet_lookup_listener(net, &tcp_hashinfo, skb,
						    ip_hdrlen(skb) +
						      __tcp_hdrlen(hp),
						    saddr, sport,
						    daddr, dport,
						    in->ifindex, 0);//查询处于listen状态的socket

			if (sk && !refcount_inc_not_zero(&sk->sk_refcnt))
				sk = NULL;
			/* NOTE: we return listeners even if bound to
			 * 0.0.0.0, those are filtered out in
			 * xt_socket, since xt_TPROXY needs 0 bound
			 * listeners too
			 */
			break;
		case NF_TPROXY_LOOKUP_ESTABLISHED:
			sk = inet_lookup_established(net, &tcp_hashinfo,
						    saddr, sport, daddr, dport,
						    in->ifindex);//查询处于established状态的socket
			/*
			对比listen状态，细心的读者应该会想到，为什么这里不增加引用计数。
			这是因为inet_lookup_established内部会增加sock计数，而inet_lookup_listener不会。
			相关commit可以查看：
			1. 3b24d854cb35 tcp/dccp: do not touch listener sk_refcnt under synflood
			2. dcbe35909c84 netfilter: tproxy: properly refcount tcp listeners
			*/
			break;
		default:
			BUG();
		}
		break;
		}
	case IPPROTO_UDP:
		sk = udp4_lib_lookup(net, saddr, sport, daddr, dport,
				     in->ifindex);
		if (sk) {
			int connected = (sk->sk_state == TCP_ESTABLISHED);
			int wildcard = (inet_sk(sk)->inet_rcv_saddr == 0);

			/* NOTE: we return listeners even if bound to
			 * 0.0.0.0, those are filtered out in
			 * xt_socket, since xt_TPROXY needs 0 bound
			 * listeners too
			 */
			if ((lookup_type == NF_TPROXY_LOOKUP_ESTABLISHED &&
			      (!connected || wildcard)) ||
			    (lookup_type == NF_TPROXY_LOOKUP_LISTENER && connected)) {//对状态进行检查
				sock_put(sk);
				sk = NULL;
			}
		}
		break;
	default:
		WARN_ON(1);
		sk = NULL;
	}

	pr_debug("tproxy socket lookup: proto %u %08x:%u -> %08x:%u, lookup type: %d, sock %p\n",
		 protocol, ntohl(saddr), ntohs(sport), ntohl(daddr), ntohs(dport), lookup_type, sk);

	return sk;
}
EXPORT_SYMBOL_GPL(nf_tproxy_get_sock_v4);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Balazs Scheidler, Krisztian Kovacs");
MODULE_DESCRIPTION("Netfilter IPv4 transparent proxy support");
