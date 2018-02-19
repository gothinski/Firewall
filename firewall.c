/*
Simple firewall
Done By : Dhruv Verma (C) 2017 gothinski
*/

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/inet.h>

//implementing filter

unsigned int telnetFilter(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *)) {
	struct iphdr *iph;
	struct tcphdr *tcph;

	iph = ip_hdr(skb);
	tcph = (void *)iph+iph->ihl*4;
/*
	//rule 1
	if (iph->protocol == IPPROTO_TCP && tcph->dest == htons(23) && iph->daddr == in_aton("10.0.2.7")){
		printk(KERN_INFO "Dropping telnet packet to %d.%d.%d.%d\n", 
			((unsigned char*)&iph->daddr)[0],
			((unsigned char*)&iph->daddr)[1],
			((unsigned char*)&iph->daddr)[2],
			((unsigned char*)&iph->daddr)[3]);
		return NF_DROP;
		}
	else {
	return NF_ACCEPT;
	}
*/
	
	//rule 4
	if (iph->protocol == IPPROTO_TCP && tcph->dest == htons(22)){
		printk(KERN_INFO "Dropping SSH packet to %d.%d.%d.%d\n", 
			((unsigned char*)&iph->daddr)[0],
			((unsigned char*)&iph->daddr)[1],
			((unsigned char*)&iph->daddr)[2],
			((unsigned char*)&iph->daddr)[3]);
		return NF_DROP;
		}
	else {
	return NF_ACCEPT;
	}
	
}


//hooking filter code to one of the netfilter hooks

static struct nf_hook_ops telnetFilterHook;

int setUpFilter(void) {
	printk(KERN_INFO "Registering a telnet filter\n");
	telnetFilterHook.hook = telnetFilter;
	telnetFilterHook.hooknum = NF_INET_POST_ROUTING;
	telnetFilterHook.pf = PF_INET;
	telnetFilterHook.priority = NF_IP_PRI_FIRST;
	nf_register_hook(&telnetFilterHook);
	return 0;
	}

void removeFilter(void){
	printk(KERN_INFO "Telnet filter is being removed\n");
	nf_unregister_hook(&telnetFilterHook);
	}

module_init(setUpFilter);
module_exit(removeFilter);








