#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/types.h>
#include <linux/list.h>
#include <linux/hashtable.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/workqueue.h>
#ifdef CONFIG_NF_CONNTRACK_CHAIN_EVENTS
#include <linux/notifier.h>
#endif
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter/x_tables.h>
#include <net/netfilter/nf_nat.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_zones.h>
#include <net/netfilter/nf_conntrack_tuple.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/nf_conntrack_ecache.h>

// nf_ct_get
// nf_ct_net
// nf_ct_zone
// xt_hooknum
// dev_put
// HOOK2MANIP
// xt_out
// xt_in
// be16_to_cpu

// nf_ct_get
struct nf_conn *rust_helper_nf_ct_get(struct sk_buff *skb, enum ip_conntrack_info *ctinfo) {
    return nf_ct_get(skb, ctinfo);
}

// nf_ct_net
struct net *rust_helper_nf_ct_net(struct nf_conn *ct) {
    return nf_ct_net(ct);
}

// nf_ct_zone
const struct nf_conntrack_zone *rust_helper_nf_ct_zone(struct nf_conn *ct) {
    return nf_ct_zone(ct);
}

// xt_hooknum
unsigned int rust_helper_xt_hooknum(const struct xt_action_param *par) {
    return xt_hooknum(par);
}

// dev_put
void rust_helper_dev_put(struct net_device *dev) {
    dev_put(dev);
}


// HOOK2MANIP (宏转为函数)
unsigned int rust_helper_HOOK2MANIP(unsigned int hooknum) {
    return HOOK2MANIP(hooknum);
}

// xt_out
struct net_device *rust_helper_xt_out(const struct xt_action_param *par) {
    return xt_out(par);
}

// xt_in
struct net_device *rust_helper_xt_in(const struct xt_action_param *par) {
    return xt_in(par);
}

// be16_to_cpu
uint16_t rust_helper_be16_to_cpu(uint16_t val) {
    return be16_to_cpu(val);
}