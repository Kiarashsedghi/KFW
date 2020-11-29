/*
 *
 *  THIS FILE CONTAINS KERNEL‌ MODULE MAIN PROGRAM
 *
 *
 *
 *  Written By :  Kiarash Sedghi
 *
 *
 * */

#include <linux/module.h>
#include <net/sock.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include<linux/init.h>
#include<linux/kernel.h>
#include<linux/kthread.h>
#include<linux/sched.h>
#include "linux/delay.h"
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/inet.h>
#include <linux/mutex.h>
#include "linux/kfw_kernel.h"
#include "linux/kfw_kernel_functions.h"


kmc_controles_t  kmc_i;

ingress_policies_t ingress_policies;

egress_policies_t egress_policies;




int firewall_starter(void*nothing){


    kmc_i.egress_kfwh = (struct nf_hook_ops*)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);

    /* Initialize netfilter hook */
    kmc_i.egress_kfwh->hook 	= (nf_hookfn*)egress_hfunc;		/* hook function */
    kmc_i.egress_kfwh->hooknum 	= NF_INET_LOCAL_OUT;		/* received packets */
    kmc_i.egress_kfwh->pf 	= PF_INET;			/* IPv4 */
    kmc_i.egress_kfwh->priority 	= NF_IP_PRI_FIRST;		/* max hook priority */

    nf_register_net_hook(&init_net, kmc_i.egress_kfwh);



    kmc_i.ingress_kfwh = (struct nf_hook_ops*)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);

    /* Initialize netfilter hook */
    kmc_i.ingress_kfwh->hook 	= (nf_hookfn*)ingress_hfunc;		/* hook function */
    kmc_i.ingress_kfwh->hooknum = NF_INET_PRE_ROUTING;		/* received packets */
    kmc_i.ingress_kfwh->pf = PF_INET;			/* IPv4 */
    kmc_i.ingress_kfwh->priority = NF_IP_PRI_FIRST;		/* max hook priority */

    nf_register_net_hook(&init_net, kmc_i.ingress_kfwh);

    return 0;
}



int talk2user_starter(void*nothing){

    kmc_i.current_kfw_policies=0;
    kmc_i.current_kfw_datas=0;
    kmc_i.negation_flag=0;

    kmc_i.port_number_array=(int *)kmalloc(50*sizeof(int),GFP_KERNEL);
    kmc_i.port_number_array_start=kmc_i.port_number_array;


    printk("Entering: %s\n",__FUNCTION__);
    struct netlink_kernel_cfg cfg = {
            .input = talk2user,
    };

    kmc_i.nl_sk = netlink_kernel_create(&init_net, NETLINK_USER, &cfg);

    if(!kmc_i.nl_sk)
    {
        printk(KERN_ALERT "Error creating socket.\n");
        return -10;
    }

    return 0;
}





static int __init kfw_kernel_init(void) {



    mutex_init(&kmc_i.thread_lock);


    kmc_i.talk2user_thread = kthread_run(&talk2user_starter,NULL,"talk2user");
    kmc_i.firewall_thread = kthread_run(&firewall_starter,NULL,"firewall_thread");



    return 0;
}

static void __exit kfw_kernel_exit(void) {

    printk(KERN_INFO "exiting kfw_kernel module\n");

    nf_unregister_net_hook(&init_net, kmc_i.egress_kfwh);
    netlink_kernel_release(kmc_i.nl_sk);
    kfree(kmc_i.egress_kfwh);

    printk(KERN_INFO "exiting done\n");



}

module_init(kfw_kernel_init);
module_exit(kfw_kernel_exit);

MODULE_LICENSE("GPL");