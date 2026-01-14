#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#include <linux/inet.h>

// static struct nf_hook_ops hook1, hook2; * changed to:
static struct nf_hook_ops hook_pre, hook_in, hook_fwd, hook_out, hook_post;
static struct nf_hook_ops hook_blockUDP;

unsigned int blockUDP(void *priv, struct sk_buff *skb,
                      const struct nf_hook_state *state)
{
   struct iphdr *iph;
   struct udphdr *udph;

   u16 port = 53;
   char ip[16] = "8.8.8.8";
   u32 ip_addr;

   if (!skb)
      return NF_ACCEPT;

   iph = ip_hdr(skb);
   // Convert the IPv4 address from dotted decimal to 32-bit binary
   in4_pton(ip, -1, (u8 *)&ip_addr, '\0', NULL);

   if (iph->protocol == IPPROTO_UDP)
   {
      udph = udp_hdr(skb);
      if (iph->daddr == ip_addr && ntohs(udph->dest) == port)
      {
         printk(KERN_WARNING "*** Dropping %pI4 (UDP), port %d\n", &(iph->daddr), port);
         return NF_DROP;
      }
   }
   return NF_ACCEPT;
}

unsigned int printInfo(void *priv, struct sk_buff *skb,
                       const struct nf_hook_state *state)
{
   struct iphdr *iph;
   char *hook;
   char *protocol;

   switch (state->hook)
   {
   case NF_INET_LOCAL_IN:
      hook = "LOCAL_IN";
      break;
   case NF_INET_LOCAL_OUT:
      hook = "LOCAL_OUT";
      break;
   case NF_INET_PRE_ROUTING:
      hook = "PRE_ROUTING";
      break;
   case NF_INET_POST_ROUTING:
      hook = "POST_ROUTING";
      break;
   case NF_INET_FORWARD:
      hook = "FORWARD";
      break;
   default:
      hook = "IMPOSSIBLE";
      break;
   }
   printk(KERN_INFO "*** %s\n", hook); // Print out the hook info

   iph = ip_hdr(skb);
   switch (iph->protocol)
   {
   case IPPROTO_UDP:
      protocol = "UDP";
      break;
   case IPPROTO_TCP:
      protocol = "TCP";
      break;
   case IPPROTO_ICMP:
      protocol = "ICMP";
      break;
   default:
      protocol = "OTHER";
      break;
   }
   // Print out the IP addresses and protocol
   printk(KERN_INFO "    %pI4  --> %pI4 (%s)\n",
          &(iph->saddr), &(iph->daddr), protocol);

   return NF_ACCEPT;
}

int registerFilter(void)
{
   printk(KERN_INFO "Registering filters.\n");

   // PRE_ROUTING
   // When a packet enters the host (before routing decision). All packets, including those destined for local processes or to be forwarded, pass here.
   hook_pre.hook = printInfo;
   hook_pre.hooknum = NF_INET_PRE_ROUTING;
   hook_pre.pf = PF_INET;
   hook_pre.priority = NF_IP_PRI_FIRST;
   nf_register_net_hook(&init_net, &hook_pre);

   // LOCAL_IN
   // When a packet is destined for the local machine. Only packets to local apps trigger this.
   hook_in.hook = printInfo;
   hook_in.hooknum = NF_INET_LOCAL_IN;
   hook_in.pf = PF_INET;
   hook_in.priority = NF_IP_PRI_FIRST;
   nf_register_net_hook(&init_net, &hook_in);

   // FORWARD
   // When a packet is being routed through the host to another interface. Only for forwarded packets.
   hook_fwd.hook = printInfo;
   hook_fwd.hooknum = NF_INET_FORWARD;
   hook_fwd.pf = PF_INET;
   hook_fwd.priority = NF_IP_PRI_FIRST;
   nf_register_net_hook(&init_net, &hook_fwd);

   // LOCAL_OUT
   // When a packet is generated locally by an app on the host.
   hook_out.hook = printInfo;
   hook_out.hooknum = NF_INET_LOCAL_OUT;
   hook_out.pf = PF_INET;
   hook_out.priority = NF_IP_PRI_FIRST;
   nf_register_net_hook(&init_net, &hook_out);

   // POST_ROUTING
   // When a packet is leaving the host, after routing. Both locally generated packets and forwarded packets pass here.
   hook_post.hook = printInfo;
   hook_post.hooknum = NF_INET_POST_ROUTING;
   hook_post.pf = PF_INET;
   hook_post.priority = NF_IP_PRI_FIRST;
   nf_register_net_hook(&init_net, &hook_post);

   // Block UDP only on POST_ROUTING
   hook_blockUDP.hook = blockUDP;
   hook_blockUDP.hooknum = NF_INET_POST_ROUTING;
   hook_blockUDP.pf = PF_INET;
   hook_blockUDP.priority = NF_IP_PRI_FIRST;
   nf_register_net_hook(&init_net, &hook_blockUDP);

   return 0;
}

void removeFilter(void)
{
   printk(KERN_INFO "The filters are being removed.\n");
   nf_unregister_net_hook(&init_net, &hook_pre);
   nf_unregister_net_hook(&init_net, &hook_in);
   nf_unregister_net_hook(&init_net, &hook_fwd);
   nf_unregister_net_hook(&init_net, &hook_out);
   nf_unregister_net_hook(&init_net, &hook_post);
   nf_unregister_net_hook(&init_net, &hook_blockUDP);
   printk(KERN_INFO "Filters removed.\n");
}

module_init(registerFilter);
module_exit(removeFilter);

MODULE_LICENSE("GPL");
