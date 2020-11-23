#include <linux/module.h>
#include <net/sock.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/kfw.h>

#include "kfw_kernel.h"
#include "kfw_kernel_functions.h"

kfwp_req_t *kfwpmss;
kfwp_reply_t *kfwprepmss;




struct sock *nl_sk = NULL;

typedef struct kmc kmc_t;

onebyte_p_t q[200];


ingress_policies_t ingress_policies;

egress_policies_t egress_policies;




kmc_controles_t  kmc_i;







static void hello_nl_recv_msg(struct sk_buff *skb) {

    struct nlmsghdr *nlh;
    int pid;
    struct sk_buff *skb_out;
    int res;
//    printk(KERN_INFO "QQ Entering: %s\n", __FUNCTION__);

    nlh = (struct nlmsghdr *) skb->data;
    kfwpmss = NLMSG_DATA(nlh);
    pid = nlh->nlmsg_pid; /*pid of sending process */


    skb_out = nlmsg_new(4, 0);

    if (!skb_out) {

        printk(KERN_ERR
        "Failed to allocate new skb\n");
        return;

    }
    nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, 4, 0);
    NETLINK_CB(skb_out).dst_group = 0; /* not in mcast group */




    // data definition
    if (kfwpmss->type == 0b00000000) {


        // copying data_name from kfwp request
        memset(kmc_i.AUX_data_name, 0, MAX_LEN_DATA_NAME);
        strcpy(kmc_i.AUX_data_name, kfwpmss->arg1);

        // copying data_type from kfwp request
        memcpy(&kmc_i.AUX_data_type, kfwpmss->arg2, 1);


        kmc_i.AUX_functions_returns = get_index_of_data_in_datas(&kmc_i, kmc_i.AUX_data_name);
        printk(KERN_INFO
        "(in:%d)", kmc_i.AUX_functions_returns);

        if (kmc_i.AUX_functions_returns == -1) {

            // This case is show data DATA_NAME
            //  send the reply indicating name does not exist
            //
            if (kmc_i.AUX_data_type != 0 && kmc_i.AUX_data_type != 1) {
                kfwprepmss = (kfwp_reply_t *) kmalloc(4, GFP_KERNEL);


                //send reply back to userspace
                kfwprepmss->status = 0b00000100;
                kfwprepmss->dg_cnt = 0;
                memcpy(nlmsg_data(nlh), kfwprepmss, 4);
                res = nlmsg_unicast(nl_sk, skb_out, pid);
                printk(KERN_INFO
                "raft \n");

                if (res < 0)
                    printk(KERN_INFO
                "Error while sending bak to user\n");
                kfree(kfwprepmss);


            } else {

                kmc_i.AUX_data_st_ptr = &(kmc_i.datas[kmc_i.current_kfw_datas]);

                // zero all that structure ( initialize )
                memset(kmc_i.AUX_data_st_ptr, 0, sizeof(data_t));


                // setting type of the new data
                //
                kmc_i.AUX_data_st_ptr->type = kmc_i.AUX_data_type;
                printk(KERN_INFO
                "(%d)\n", kmc_i.AUX_data_st_ptr->type);

                // setting name of the new data
                strcpy(kmc_i.AUX_data_st_ptr->name, kmc_i.AUX_data_name);
                printk(KERN_INFO
                "(%s)\n", kmc_i.AUX_data_name);
//
                // update total number of datas_cache in kfw datas_cache
                kmc_i.current_kfw_datas++;


//            printk(KERN_ERR "new data created%s %d\n",kmc_i.datas_cache[0].name,kmc_i.datas_cache[0].type);
                printk(KERN_INFO
                ">(%s)\n", kmc_i.datas[0].name);
                printk(KERN_INFO
                ">(%d)\n", kmc_i.datas[0].type);
                printk(KERN_INFO
                ">(%s)\n", kmc_i.datas[1].name);
                printk(KERN_INFO
                ">(%d)\n", kmc_i.datas[1].type);


                skb_out = nlmsg_new(4, 0);

                if (!skb_out) {

                    printk(KERN_ERR
                    "Failed to allocate new skb\n");
                    return;

                }
                nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, 4, 0);
                NETLINK_CB(skb_out).dst_group = 0; /* not in mcast group */

                kfwprepmss = (kfwp_reply_t *) kmalloc(4, GFP_KERNEL);


                //send reply back to userspace
                kfwprepmss->status = 0b00000000;
                kfwprepmss->dg_cnt = 0;
                memcpy(nlmsg_data(nlh), kfwprepmss, 4);
                res = nlmsg_unicast(nl_sk, skb_out, pid);
                printk(KERN_INFO
                "raft \n");

                if (res < 0)
                    printk(KERN_INFO
                "Error while sending bak to user\n");
                kfree(kfwprepmss);

            }

        } else {
            printk(KERN_INFO
            "inja\n");

            /* We should check whether data_type specified by user_command matches
             * data_type of the data we have found.
             *
             * Users Cannot change the type whenever they enter data definition mode.
            */

            // kernel just check type 0 & 1 , other types means type is not important.
            // cases like show data DATA_NAME set type to values other than 0 or 1
            if ((kmc_i.AUX_data_type == 0 || kmc_i.AUX_data_type == 1) &&
                kmc_i.datas[kmc_i.AUX_functions_returns].type != kmc_i.AUX_data_type) {
                //send reply back to userspace
                kfwprepmss = (kfwp_reply_t *) kmalloc(4, GFP_KERNEL);

                kfwprepmss->status = 0b00000001;
                kfwprepmss->dg_cnt = 0;
                printk(KERN_INFO
                "inja2\n");

                memcpy(nlmsg_data(nlh), kfwprepmss, 4);
                res = nlmsg_unicast(nl_sk, skb_out, pid);
                printk(KERN_INFO
                "inja3\n");

                if (res < 0)
                    printk(KERN_INFO
                "Error while sending bak to user\n");
                kfree(kfwprepmss);
            } else {
                kmc_i.AUX_data_st_ptr = &(kmc_i.datas[kmc_i.AUX_functions_returns]);
                printk(KERN_INFO
                "$$$%d$$\n", kmc_i.AUX_data_st_ptr->current_rules);


                if (kmc_i.AUX_data_st_ptr->current_rules != 0) {

                    kfwprepmss = (kfwp_reply_t *) kmalloc(4, GFP_KERNEL);

                    kfwprepmss->status = 0b00000000;
                    kfwprepmss->dg_size = 200;
                    kfwprepmss->dg_cnt = ((int) (sizeof(data_t) / kfwprepmss->dg_size)) + 1;

                    printk(KERN_INFO
                    "cnt{%d}\n", kfwprepmss->dg_cnt);
                    printk(KERN_INFO
                    "dgsize{%d}\n", kfwprepmss->dg_size);



//                    memcpy(kfwprepmss->payload, &kmc_i.datas_cache[kmc_i.AUX_functions_returns], sizeof(data_t));
//                    printk(KERN_INFO
//                    "inja2\n");

                    memcpy(nlmsg_data(nlh), kfwprepmss, 4);
                    res = nlmsg_unicast(nl_sk, skb_out, pid);
                    printk(KERN_INFO
                    "inja3\n");

                    if (res < 0)
                        printk(KERN_INFO
                    "Error while sending bak to user\n");

                    memcpy(q, kmc_i.AUX_data_st_ptr, 200);
                    printk(KERN_INFO
                    "q:> %d\n", *(q + 12));


                    // reallocate for simple reply
                    int i = 0;
                    for (i = 0; i < kfwprepmss->dg_cnt; i++) {

                        skb_out = nlmsg_new(kfwprepmss->dg_size, 0);
                        if (!skb_out) {

                            printk(KERN_ERR
                            "Failed to allocate new skb\n");
                            return;

                        }
                        nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, kfwprepmss->dg_size, 0);
                        NETLINK_CB(skb_out).dst_group = 0; /* not in mcast group */

                        printk(KERN_INFO
                        "%d\n", i);

                        if (i == kfwprepmss->dg_cnt - 1) {
                            memcpy(q, (void *) kmc_i.AUX_data_st_ptr + i * kfwprepmss->dg_size,
                                   sizeof(data_t) - i * kfwprepmss->dg_size + 1);
                            printk(KERN_INFO
                            "%d\n", sizeof(data_t) - i * kfwprepmss->dg_size);

                            memcpy(nlmsg_data(nlh), q, kfwprepmss->dg_size);
                        } else {

                            memcpy(nlmsg_data(nlh), (void *) kmc_i.AUX_data_st_ptr + i * kfwprepmss->dg_size,
                                   kfwprepmss->dg_size);
                        }
                        res = nlmsg_unicast(nl_sk, skb_out, pid);
//
                        printk(KERN_INFO
                        "inja33333333\n");
                        if (res < 0)
                            printk(KERN_INFO
                        "Error while sending bak to user\n");
                    }


                    kfree(kfwprepmss);
                } else {
                    //send reply back to userspace
                    kfwprepmss = (kfwp_reply_t *) kmalloc(4, GFP_KERNEL);

                    kfwprepmss->status = 0b00000000;
                    kfwprepmss->dg_cnt = 0;
                    memcpy(nlmsg_data(nlh), kfwprepmss, 4);
                    res = nlmsg_unicast(nl_sk, skb_out, pid);
                    printk(KERN_INFO
                    "raft injajaja \n");

                    if (res < 0)
                        printk(KERN_INFO
                    "Error while sending bak to user\n");
                    kfree(kfwprepmss);

                }

            }

        }

    }


        // rule definition
    else if (kfwpmss->type == 0b00000001) {

        // copying rule_type from kfwp request
        memset(kmc_i.AUX_data_name, 0, MAX_LEN_DATA_NAME);
        memset(kmc_i.AUX_rule_type, 0, MAX_LEN_RULE_TYPE);
        memset(kmc_i.AUX_rule_value, 0, MAX_LEN_RULE_VALUE);

        strcpy(kmc_i.AUX_rule_type, kfwpmss->arg1);
        strcpy(kmc_i.AUX_rule_value, kfwpmss->arg2);
        strcpy(kmc_i.AUX_data_name, kfwpmss->context);

        kmc_i.AUX_functions_returns = get_index_of_rule_in_rules(kmc_i.AUX_data_st_ptr, kmc_i.AUX_rule_type);

        if (kmc_i.AUX_functions_returns == -1) {

            kmc_i.AUX_rule_st_ptr = &(kmc_i.AUX_data_st_ptr->rules[kmc_i.AUX_data_st_ptr->current_rules]);
            //zero the data_with_action
            memset(kmc_i.AUX_rule_st_ptr, 0, sizeof(rule_t));

            strcpy(kmc_i.AUX_rule_st_ptr->type, kmc_i.AUX_rule_type);
            strcpy(kmc_i.AUX_rule_st_ptr->value, kmc_i.AUX_rule_value);

            printk(KERN_INFO
            "rule added %s\n", kmc_i.AUX_rule_st_ptr->type);
            printk(KERN_INFO
            "rule added %s\n", kmc_i.AUX_rule_st_ptr->value);

            //update total number of rules in data
            kmc_i.AUX_data_st_ptr->current_rules++;
            printk(KERN_INFO
            "rule added \n");
            printk(KERN_INFO
            "#: %d\n", kmc_i.AUX_data_st_ptr->current_rules);

            kfwprepmss = (kfwp_reply_t *) kmalloc(4, GFP_KERNEL);

            kfwprepmss->status = 0b00000000;
            kfwprepmss->dg_cnt = 0;
            memcpy(nlmsg_data(nlh), kfwprepmss, 4);
            res = nlmsg_unicast(nl_sk, skb_out, pid);
            printk(KERN_INFO
            "raft \n");

            if (res < 0)
                printk(KERN_INFO
            "Error while sending bak to user\n");
            kfree(kfwprepmss);

        } else {

            kmc_i.AUX_rule_st_ptr = &(kmc_i.AUX_data_st_ptr->rules[kmc_i.AUX_functions_returns]);
            memset(kmc_i.AUX_rule_st_ptr->value, 0, strlen(kmc_i.AUX_rule_st_ptr->value));
            strcpy((kmc_i.AUX_rule_st_ptr->value), kmc_i.AUX_rule_value);
            printk(KERN_INFO
            "rule changed \n");

            kfwprepmss = (kfwp_reply_t *) kmalloc(4, GFP_KERNEL);

            kfwprepmss->status = 0b00000000;
            kfwprepmss->dg_cnt = 0;
            memcpy(nlmsg_data(nlh), kfwprepmss, 4);
            res = nlmsg_unicast(nl_sk, skb_out, pid);
            printk(KERN_INFO
            "raft k\n");

            if (res < 0)
                printk(KERN_INFO
            "Error while sending bak to user\n");
            kfree(kfwprepmss);
        }
//
//        printk(KERN_INFO "(val:%s)\n",kmc_i.AUX_rule_type);
//        printk(KERN_INFO "(ty:%s)\n",kmc_i.AUX_rule_value);
//        printk(KERN_INFO "(ctx:%s)\n",kmc_i.AUX_data_name);
//        printk(KERN_INFO "(ctx:%d)\n",kmc_i.AUX_functions_returns);

    }

        // rule deletion
    else if (kfwpmss->type == 0b10000001) {
        printk(KERN_INFO
        "rule deletion \n");

        // copying rule_type from kfwp request
        memset(kmc_i.AUX_rule_type, 0, MAX_LEN_RULE_TYPE);

        strcpy(kmc_i.AUX_rule_type, kfwpmss->arg1);
        printk(KERN_INFO
        "deletion of %s \n", kmc_i.AUX_rule_type);


/*
         * Deletion policy:
         *  First we find the type and value of the rule based on splitting
         *  rule command.Then we search these values in the rules array of the
         *  (founded/created) data.After finding the index of that rule , we start
         *  shifting the right side rules to the left.For efficiency purposes the logic is
         *  as below‌:
         *          if ( the rule was the last rule in the array){
         *
         *              // checking this is because an array with one element
         *              // can serves its first element as its last element , so
         *              // we have to check if it has only 1 element in itself
         *              // decrementing is not necessary and the reason is
         *              // whenever we want to add new element to any array in this program
         *              // we use bzero() to clear its previous data , so we are not worried about
         *              // previous data of first element.
         *
         *              if(decrementing of total number does not lead to -1)
         *                  just decrement one from total number of rules in the array
         *          }
         *          else{
         *             go to the next rule;
         *             start copying each rules bytes to the previous index
         *         }

         * */





        // Start searching for the rule based on Type  and Value
        int i;
        for (i = 0; i < kmc_i.AUX_data_st_ptr->current_rules; i++) {
            // we check just rule_type
            if (strcmp(kmc_i.AUX_data_st_ptr->rules[i].type, kmc_i.AUX_rule_type) == 0) {
                // here we have found the rule

                // check if the rule is the last one
                if (i == kmc_i.AUX_data_st_ptr->current_rules - 1) {
                    if (kmc_i.AUX_data_st_ptr->current_rules - 1 != -1)
                        kmc_i.AUX_data_st_ptr->current_rules--;
                } else {
                    // i++ : go to next rule
                    i++;
                    // start copying each rule to the previous index ( shifting to the left)
                    while (i <= kmc_i.AUX_data_st_ptr->current_rules - 1) {
                        memcpy(&kmc_i.AUX_data_st_ptr->rules[i - 1], &kmc_i.AUX_data_st_ptr->rules[i], sizeof(rule_t));
                        i++;
                    }
                    // update total number of rules
                    kmc_i.AUX_data_st_ptr->current_rules--;
                }
                break;

            }
        }


        printk(KERN_INFO
        "rule deletion %s\n", kmc_i.AUX_data_st_ptr->name);
        printk(KERN_INFO
        "rule deletion %d\n", kmc_i.AUX_data_st_ptr->current_rules);

        kfwprepmss = (kfwp_reply_t *) kmalloc(4, GFP_KERNEL);

        // send reply to userspace
        kfwprepmss->status = 0b00000000;
        kfwprepmss->dg_cnt = 0;
        memcpy(nlmsg_data(nlh), kfwprepmss, 4);
        res = nlmsg_unicast(nl_sk, skb_out, pid);
        printk(KERN_INFO
        "deleted mss raft \n");

        if (res < 0)
            printk(KERN_INFO
        "Error while sending bak to user\n");

        kfree(kfwprepmss);


    }

        // clear rules of the data
    else if (kfwpmss->type == 0b01111110) {
        kmc_i.AUX_data_st_ptr->current_rules = 0;
        printk(KERN_INFO
        "cuu rules : %d\n", kmc_i.AUX_data_st_ptr->current_rules);

        kfwprepmss = (kfwp_reply_t *) kmalloc(4, GFP_KERNEL);

        // send reply to userspace
        kfwprepmss->status = 0b00000000;
        kfwprepmss->dg_cnt = 0;
        memcpy(nlmsg_data(nlh), kfwprepmss, 4);
        res = nlmsg_unicast(nl_sk, skb_out, pid);
        printk(KERN_INFO
        "deleted mss raft \n");

        if (res < 0)
            printk(KERN_INFO
        "Error while sending bak to user\n");

        kfree(kfwprepmss);
    }



        // clear data_with of the policy
    else if (kfwpmss->type == 0b01111111) {
        printk(KERN_INFO
        "before data_with_actions : %d\n", kmc_i.AUX_policy_st_ptr->current_data_actions);

        kmc_i.AUX_policy_st_ptr->current_data_actions = 0;
        printk(KERN_INFO
        "after data_with_actions : %d\n", kmc_i.AUX_policy_st_ptr->current_data_actions);

        kfwprepmss = (kfwp_reply_t *) kmalloc(4, GFP_KERNEL);

        // send reply to userspace
        kfwprepmss->status = 0b00000000;
        kfwprepmss->dg_cnt = 0;
        memcpy(nlmsg_data(nlh), kfwprepmss, 4);
        res = nlmsg_unicast(nl_sk, skb_out, pid);
        printk(KERN_INFO
        "rules cleared mss raft \n");

        if (res < 0)
            printk(KERN_INFO
        "Error while sending bak to user\n");

        kfree(kfwprepmss);
    }


        // policy definition
    else if (kfwpmss->type == 0b00000010) {

        memset(kmc_i.AUX_policy_name, 0, MAX_LEN_POLICY_NAME);


        strcpy(kmc_i.AUX_policy_name, kfwpmss->arg1);


        printk(KERN_INFO
        "policy name %s \n", kmc_i.AUX_policy_name);


        kmc_i.AUX_functions_returns = get_index_of_policy_in_policies(&kmc_i, kmc_i.AUX_policy_name);
        printk(KERN_INFO
        "policy name : %s(in:%d)\n", kmc_i.AUX_policy_name, kmc_i.AUX_functions_returns);


        if (kmc_i.AUX_functions_returns == -1) {

            // check if the command issued was show command
            // if sth was written on arg2 means show command was issued
            if (*kfwpmss->arg2 != 0) {
                printk(KERN_INFO
                "show policy command issued\n");

                kfwprepmss = (kfwp_reply_t *) kmalloc(4, GFP_KERNEL);
                //send reply back to userspace
                kfwprepmss->status = 0b00000100;
                kfwprepmss->dg_cnt = 0;
                memcpy(nlmsg_data(nlh), kfwprepmss, 4);
                res = nlmsg_unicast(nl_sk, skb_out, pid);
                printk(KERN_INFO
                "show policy raft \n");

                if (res < 0)
                    printk(KERN_INFO
                "Error while sending bak to user\n");
                kfree(kfwprepmss);


            } else {

                kmc_i.AUX_policy_st_ptr = &(kmc_i.policies[kmc_i.current_kfw_policies]);

                // zero all that structure ( initialize )
                memset(kmc_i.AUX_policy_st_ptr, 0, sizeof(policy_t));


                // setting name of the new policy
                //

                // setting name of the new data
                strcpy(kmc_i.AUX_policy_st_ptr->name, kmc_i.AUX_policy_name);
                printk(KERN_INFO
                "name in structure(%s)\n", kmc_i.AUX_policy_st_ptr->name);
//
                // update total number of datas_cache in kfw datas_cache
                kmc_i.current_kfw_policies++;


//            printk(KERN_ERR "new data created%s %d\n",kmc_i.datas_cache[0].name,kmc_i.datas_cache[0].type);
                printk(KERN_INFO
                ">(%s)\n", kmc_i.policies[0].name);

                printk(KERN_INFO
                ">(%s)\n", kmc_i.policies[1].name);


                skb_out = nlmsg_new(4, 0);

                if (!skb_out) {

                    printk(KERN_ERR
                    "Failed to allocate new skb\n");
                    return;

                }
                nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, 4, 0);
                NETLINK_CB(skb_out).dst_group = 0; /* not in mcast group */

                kfwprepmss = (kfwp_reply_t *) kmalloc(4, GFP_KERNEL);


                //send reply back to userspace
                kfwprepmss->status = 0b00000000;
                kfwprepmss->dg_cnt = 0;
                memcpy(nlmsg_data(nlh), kfwprepmss, 4);
                res = nlmsg_unicast(nl_sk, skb_out, pid);
                printk(KERN_INFO
                "policy definition raft \n");

                if (res < 0)
                    printk(KERN_INFO
                "Error while sending bak to user\n");
                kfree(kfwprepmss);
            }

        } else {
            printk(KERN_INFO
            "policyie hastesh inja\n");


            kmc_i.AUX_policy_st_ptr = &(kmc_i.policies[kmc_i.AUX_functions_returns]);
            printk(KERN_INFO
            "$$$%d$$\n", kmc_i.AUX_policy_st_ptr->current_data_actions);


            if (kmc_i.AUX_policy_st_ptr->current_data_actions != 0) {

                kfwprepmss = (kfwp_reply_t *) kmalloc(4, GFP_KERNEL);

                kfwprepmss->status = 0b00000000;
                kfwprepmss->dg_size = 200;
                kfwprepmss->dg_cnt = ((int) (sizeof(policy_t) / kfwprepmss->dg_size)) + 1;

                printk(KERN_INFO
                "cnt{%d}\n", kfwprepmss->dg_cnt);
                printk(KERN_INFO
                "dgsize{%d}\n", kfwprepmss->dg_size);



//                    memcpy(kfwprepmss->payload, &kmc_i.datas_cache[kmc_i.AUX_functions_returns], sizeof(data_t));
//                    printk(KERN_INFO
//                    "inja2\n");

                memcpy(nlmsg_data(nlh), kfwprepmss, 4);
                res = nlmsg_unicast(nl_sk, skb_out, pid);
                printk(KERN_INFO
                "reply radt ke bege data dare ya na\n");

                if (res < 0)
                    printk(KERN_INFO
                "Error while sending bak to user\n");

                memcpy(q, kmc_i.AUX_data_st_ptr, 200);
                printk(KERN_INFO
                "q:> %d\n", *(q + 12));


                // reallocate for simple reply
                int i = 0;
                for (i = 0; i < kfwprepmss->dg_cnt; i++) {

                    skb_out = nlmsg_new(kfwprepmss->dg_size, 0);
                    if (!skb_out) {

                        printk(KERN_ERR
                        "Failed to allocate new skb\n");
                        return;

                    }
                    nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, kfwprepmss->dg_size, 0);
                    NETLINK_CB(skb_out).dst_group = 0; /* not in mcast group */

                    printk(KERN_INFO
                    "%d\n", i);

                    if (i == kfwprepmss->dg_cnt - 1) {
                        memcpy(q, (void *) kmc_i.AUX_policy_st_ptr + i * kfwprepmss->dg_size,
                               sizeof(policy_t) - i * kfwprepmss->dg_size + 1);

                        printk(KERN_INFO
                        "%d\n", sizeof(policy_t) - i * kfwprepmss->dg_size);

                        memcpy(nlmsg_data(nlh), q, kfwprepmss->dg_size);
                    } else {

                        memcpy(nlmsg_data(nlh), (void *) kmc_i.AUX_policy_st_ptr + i * kfwprepmss->dg_size,
                               kfwprepmss->dg_size);
                    }
                    res = nlmsg_unicast(nl_sk, skb_out, pid);
//
                    printk(KERN_INFO
                    "inja33333333\n");
                    if (res < 0)
                        printk(KERN_INFO
                    "Error while sending bak to user\n");
                }


                kfree(kfwprepmss);
            } else {
                //send reply back to userspace
                kfwprepmss = (kfwp_reply_t *) kmalloc(4, GFP_KERNEL);

                kfwprepmss->status = 0b00000000;
                kfwprepmss->dg_cnt = 0;
                memcpy(nlmsg_data(nlh), kfwprepmss, 4);
                res = nlmsg_unicast(nl_sk, skb_out, pid);
                printk(KERN_INFO
                "raft policiye data_action nadasht k befreste \n");

                if (res < 0)
                    printk(KERN_INFO
                "Error while sending bak to user\n");
                kfree(kfwprepmss);

            }

        }

    }


        // policy deletion
    else if (kfwpmss->type == 0b10000010) {
        memset(kmc_i.AUX_policy_name, 0, MAX_LEN_POLICY_NAME);


        strcpy(kmc_i.AUX_policy_name, kfwpmss->arg1);


        printk(KERN_INFO
        "policy name to delete %s \n", kmc_i.AUX_policy_name);


        // delete the policy
        kmc_i.AUX_functions_returns = get_index_of_policy_in_policies(&kmc_i, kmc_i.AUX_policy_name);

        // deletion policy is same as before
        if (kmc_i.AUX_functions_returns != -1) {

            printk(KERN_INFO
            "#ingress %d\n", ingress_policies.current_ingress_policies);

            kmc_i.AUX_functions_returns = check_ingress_dependency_on_policy(&ingress_policies, kmc_i.AUX_policy_name);

            if (kmc_i.AUX_functions_returns != -1) {
                //send reply back to userspace telling an ingress policy exists
                // that relie on the policy , cannot delete policy
                kfwprepmss = (kfwp_reply_t *) kmalloc(4, GFP_KERNEL);

                kfwprepmss->status = 0b00000001;
                kfwprepmss->dg_cnt = 0;
                memcpy(nlmsg_data(nlh), kfwprepmss, 4);
                res = nlmsg_unicast(nl_sk, skb_out, pid);
                printk(KERN_INFO
                "ingress relies on the policy & cannot delete the policy \n");

                if (res < 0)
                    printk(KERN_INFO
                "Error while sending bak to user\n");
                kfree(kfwprepmss);
            } else {
                kmc_i.AUX_functions_returns = check_egress_dependency_on_policy(&egress_policies,
                                                                                kmc_i.AUX_policy_name);

                if (kmc_i.AUX_functions_returns != -1) {
                    //send reply back to userspace telling an egress policy exists
                    // that relie on the policy , cannot delete policy
                    kfwprepmss = (kfwp_reply_t *) kmalloc(4, GFP_KERNEL);

                    kfwprepmss->status = 0b00000010;
                    kfwprepmss->dg_cnt = 0;
                    memcpy(nlmsg_data(nlh), kfwprepmss, 4);
                    res = nlmsg_unicast(nl_sk, skb_out, pid);
                    printk(KERN_INFO
                    "egress relies on the policy & cannot delete the policy \n");

                    if (res < 0)
                        printk(KERN_INFO
                    "Error while sending bak to user\n");
                    kfree(kfwprepmss);

                } else {

                    // deletion policy is same as before
                    if (kmc_i.AUX_functions_returns == kmc_i.current_kfw_policies - 1) {
                        if (kmc_i.current_kfw_policies - 1 != -1)
                            kmc_i.current_kfw_policies--;
                    } else {
                        kmc_i.AUX_functions_returns++;
                        while (kmc_i.AUX_functions_returns <= kmc_i.current_kfw_policies - 1) {
                            memcpy(&kmc_i.policies[kmc_i.AUX_functions_returns - 1],
                                   &kmc_i.policies[kmc_i.AUX_functions_returns], sizeof(policy_t));
                            kmc_i.AUX_functions_returns++;
                        }
                        //update total number of policies_cache
                        kmc_i.current_kfw_policies--;
                    }


                    //send reply back to userspace telling an the policy
                    // was deleted successfully
                    kfwprepmss = (kfwp_reply_t *) kmalloc(4, GFP_KERNEL);

                    kfwprepmss->status = 0b00000000;
                    kfwprepmss->dg_cnt = 0;
                    memcpy(nlmsg_data(nlh), kfwprepmss, 4);
                    res = nlmsg_unicast(nl_sk, skb_out, pid);
                    printk(KERN_INFO
                    "policy deleted successfully \n");

                    if (res < 0)
                        printk(KERN_INFO
                    "Error while sending bak to user\n");
                    kfree(kfwprepmss);


                }
            }

        } else {
            //send reply back to userspace telling an the policy
            // does not exist
            kfwprepmss = (kfwp_reply_t *) kmalloc(4, GFP_KERNEL);

            kfwprepmss->status = 0b00000011;
            kfwprepmss->dg_cnt = 0;
            memcpy(nlmsg_data(nlh), kfwprepmss, 4);
            res = nlmsg_unicast(nl_sk, skb_out, pid);
            printk(KERN_INFO
            "policy specified does not exist \n");

            if (res < 0)
                printk(KERN_INFO
            "Error while sending bak to user\n");
            kfree(kfwprepmss);

        }


    }


//
        // data with action definition
    else if (kfwpmss->type == 0b00000011) {
        printk(KERN_INFO
        "data with action definition \n");

        // copying rule_type from kfwp request
        memset(kmc_i.AUX_data_name, 0, MAX_LEN_DATA_NAME);
        memset(kmc_i.AUX_action_name, 0, MAX_LEN_ACTION_NAME);

        strcpy(kmc_i.AUX_data_name, kfwpmss->arg1);
        strcpy(kmc_i.AUX_action_name, kfwpmss->arg2);

        printk(KERN_INFO
        "data_name: %s \n", kmc_i.AUX_data_name);

        printk(KERN_INFO
        "action : %s \n", kmc_i.AUX_action_name);


        kmc_i.AUX_functions_returns = get_index_of_data_in_datas(&kmc_i, kmc_i.AUX_data_name);

        if (kmc_i.AUX_functions_returns == -1) {

            kfwprepmss = (kfwp_reply_t *) kmalloc(4, GFP_KERNEL);


            //send reply back to userspace
            // saying error of not existance of the data
            kfwprepmss->status = 0b00000001;
            kfwprepmss->dg_cnt = 0;
            memcpy(nlmsg_data(nlh), kfwprepmss, 4);
            res = nlmsg_unicast(nl_sk, skb_out, pid);
            printk(KERN_INFO
            "data not exist raft \n");

            if (res < 0)
                printk(KERN_INFO
            "Error while sending bak to user\n");
            kfree(kfwprepmss);

        } else {
            printk(KERN_INFO
            "miad inja ke data e hast \n");


            kmc_i.AUX_functions_returns = get_index_of_datawithaction_in_policies(kmc_i.AUX_policy_st_ptr,
                                                                                  kmc_i.AUX_data_name);


            printk(KERN_INFO
            "dataaction exist %d \n", kmc_i.AUX_functions_returns);


            if (kmc_i.AUX_functions_returns == -1) {

                kmc_i.AUX_data_action_st_ptr = &(kmc_i.AUX_policy_st_ptr->data_with_actions[kmc_i.AUX_policy_st_ptr->current_data_actions]);

                //zero the data_with_action
                memset(kmc_i.AUX_data_action_st_ptr, 0, sizeof(data_with_action_t));

                strcpy(kmc_i.AUX_data_action_st_ptr->data_name, kmc_i.AUX_data_name);
                strcpy(kmc_i.AUX_data_action_st_ptr->action, kmc_i.AUX_action_name);

                // update total number of data_with_action entities in the policy
                kmc_i.AUX_policy_st_ptr->current_data_actions++;

                kfwprepmss = (kfwp_reply_t *) kmalloc(4, GFP_KERNEL);

                //send reply back to userspace
                // saying creation of data_with_action_successful
                kfwprepmss->status = 0b00000000;
                kfwprepmss->dg_cnt = 0;
                memcpy(nlmsg_data(nlh), kfwprepmss, 4);
                res = nlmsg_unicast(nl_sk, skb_out, pid);
                printk(KERN_INFO
                "data creation raft \n");

                if (res < 0)
                    printk(KERN_INFO
                "Error while sending bak to user\n");
                kfree(kfwprepmss);


            } else {
                kmc_i.AUX_data_action_st_ptr = &(kmc_i.AUX_policy_st_ptr->data_with_actions[kmc_i.AUX_functions_returns]);

                memset(&(kmc_i.AUX_data_action_st_ptr->action), 0, MAX_LEN_ACTION_NAME);

                strcpy(kmc_i.AUX_data_action_st_ptr->action, kmc_i.AUX_action_name);

                kfwprepmss = (kfwp_reply_t *) kmalloc(4, GFP_KERNEL);

                //send reply back to userspace
                // saying creation of data_with_action_successful
                kfwprepmss->status = 0b00000000;
                kfwprepmss->dg_cnt = 0;
                memcpy(nlmsg_data(nlh), kfwprepmss, 4);
                res = nlmsg_unicast(nl_sk, skb_out, pid);
                printk(KERN_INFO
                "data with action changed raft \n");

                if (res < 0)
                    printk(KERN_INFO
                "Error while sending bak to user\n");
                kfree(kfwprepmss);


            }
        }
    }

        // data with action deletion
    else if (kfwpmss->type == 0b10000011) {


        printk(KERN_INFO
        "data with action DELETION \n");

        // copying rule_type from kfwp request
        memset(kmc_i.AUX_data_name, 0, MAX_LEN_DATA_NAME);
        memset(kmc_i.AUX_action_name, 0, MAX_LEN_ACTION_NAME);

        strcpy(kmc_i.AUX_data_name, kfwpmss->arg1);
        strcpy(kmc_i.AUX_action_name, kfwpmss->arg2);

        printk(KERN_INFO
        "data_name: %s \n", kmc_i.AUX_data_name);

        printk(KERN_INFO
        "action : %s \n", kmc_i.AUX_action_name);


        //TODO‌ change algor to the past

        // logic is same as before
        int i;
        for (i = 0; i < kmc_i.AUX_policy_st_ptr->current_data_actions; i++) {
            // we check just data_name
            if (strcmp(kmc_i.AUX_policy_st_ptr->data_with_actions[i].data_name, kmc_i.AUX_data_name) == 0) {
                // here we have found the data

                // check if the rule is the last one
                if (i == kmc_i.AUX_policy_st_ptr->current_data_actions - 1) {
                    if (kmc_i.AUX_policy_st_ptr->current_data_actions - 1 != -1)
                        kmc_i.AUX_policy_st_ptr->current_data_actions--;
                } else {
                    // i++ : go to next rule
                    i++;
                    // start copying each rule to the previous index ( shifting to the left)
                    while (i <= kmc_i.AUX_policy_st_ptr->current_data_actions - 1) {
                        memcpy(&kmc_i.AUX_policy_st_ptr->data_with_actions[i - 1],
                               &kmc_i.AUX_policy_st_ptr->data_with_actions[i], sizeof(data_with_action_t));
                        i++;
                    }
                    // update total number of rules
                    kmc_i.AUX_policy_st_ptr->current_data_actions--;
                }
                break;

            }
        }


        kfwprepmss = (kfwp_reply_t *) kmalloc(4, GFP_KERNEL);

        // send reply to userspace
        kfwprepmss->status = 0b00000000;
        kfwprepmss->dg_cnt = 0;
        memcpy(nlmsg_data(nlh), kfwprepmss, 4);
        res = nlmsg_unicast(nl_sk, skb_out, pid);
        printk(KERN_INFO
        "rule deletion success \n");

        if (res < 0)
            printk(KERN_INFO
        "Error while sending bak to user\n");

        kfree(kfwprepmss);


    }


        // data deletion
    else if (kfwpmss->type == 0b10000000) {

        // copying data_name from kfwp request
        memset(kmc_i.AUX_data_name, 0, MAX_LEN_DATA_NAME);
        strcpy(kmc_i.AUX_data_name, kfwpmss->arg1);

        kmc_i.AUX_functions_returns = get_index_of_data_in_datas(&kmc_i, kmc_i.AUX_data_name);

        if (kmc_i.AUX_functions_returns != -1) {

            // check policy dependecy
            kmc_i.AUX_functions_returns = check_policy_dependeny_on_data(&kmc_i, kmc_i.AUX_data_name);

            // data cannot be deleted because there are some policies_cache that
            // depends on this data
            if (kmc_i.AUX_functions_returns != -1) {
                // send reply to userspace indicating that this data cannot be deleted becuase of
                // dependency

                kfwprepmss = (kfwp_reply_t *) kmalloc(4, GFP_KERNEL);

                // send reply to userspace
                kfwprepmss->status = 0b00000011;
                kfwprepmss->dg_cnt = 0;
                memcpy(nlmsg_data(nlh), kfwprepmss, 4);
                res = nlmsg_unicast(nl_sk, skb_out, pid);
                printk(KERN_INFO
                "data cannot be deleted because of dependency \n");

                if (res < 0)
                    printk(KERN_INFO
                "Error while sending bak to user\n");

                kfree(kfwprepmss);

            } else {
                kmc_i.AUX_functions_returns = get_index_of_data_in_datas(&kmc_i, kmc_i.AUX_data_name);

                // Delete the data from datas_cache array.
                // Deletion policy is same as before.
                if (kmc_i.AUX_functions_returns == kmc_i.current_kfw_datas - 1) {
                    if (kmc_i.current_kfw_datas - 1 != -1)
                        kmc_i.current_kfw_datas--;
                } else {
                    kmc_i.AUX_functions_returns++;
                    while (kmc_i.AUX_functions_returns <= kmc_i.current_kfw_datas - 1) {
                        memcpy(&kmc_i.datas[kmc_i.AUX_functions_returns - 1], &kmc_i.datas[kmc_i.AUX_functions_returns],
                               sizeof(data_t));
                        kmc_i.AUX_functions_returns++;
                    }
                    //update total number of datas_cache
                    kmc_i.current_kfw_datas--;
                }

                // send reply to userspace indicating that this data does not exist
                kfwprepmss = (kfwp_reply_t *) kmalloc(4, GFP_KERNEL);

                // send reply to userspace
                kfwprepmss->status = 0b00000000;
                kfwprepmss->dg_cnt = 0;
                memcpy(nlmsg_data(nlh), kfwprepmss, 4);
                res = nlmsg_unicast(nl_sk, skb_out, pid);
                printk(KERN_INFO
                "data_name does not exist to delete \n");

                if (res < 0)
                    printk(KERN_INFO
                "Error while sending bak to user\n");

                kfree(kfwprepmss);


            }

        } else {
            // send reply to userspace indicating that this data does not exist
            kfwprepmss = (kfwp_reply_t *) kmalloc(4, GFP_KERNEL);

            // send reply to userspace
            kfwprepmss->status = 0b00000010;
            kfwprepmss->dg_cnt = 0;
            memcpy(nlmsg_data(nlh), kfwprepmss, 4);
            res = nlmsg_unicast(nl_sk, skb_out, pid);
            printk(KERN_INFO
            "data_name does not exist to delete \n");

            if (res < 0)
                printk(KERN_INFO
            "Error while sending bak to user\n");

            kfree(kfwprepmss);

        }


    }


        //show datas_cache
    else if (kfwpmss->type == 0b00001110) {

        kfwprepmss = (kfwp_reply_t *) kmalloc(4, GFP_KERNEL);

        kfwprepmss->status = 0b00000000;
        kfwprepmss->dg_size = 13; //TODO‌ make this a macro
        kfwprepmss->dg_cnt = kmc_i.current_kfw_datas;

        printk(KERN_INFO
        "cnt{%d}\n", kfwprepmss->dg_cnt);
        printk(KERN_INFO
        "dgsize{%d}\n", kfwprepmss->dg_size);



//                    memcpy(kfwprepmss->payload, &kmc_i.datas_cache[kmc_i.AUX_functions_returns], sizeof(data_t));
//                    printk(KERN_INFO
//                    "inja2\n");

        memcpy(nlmsg_data(nlh), kfwprepmss, 4);
        res = nlmsg_unicast(nl_sk, skb_out, pid);
        printk(KERN_INFO
        "inja3\n");

        if (res < 0)
            printk(KERN_INFO
        "Error while sending bak to user\n");


//
        int i = 0;
        for (i = 0; i < kfwprepmss->dg_cnt; i++) {

            skb_out = nlmsg_new(kfwprepmss->dg_size, 0);
            if (!skb_out) {

                printk(KERN_ERR
                "Failed to allocate new skb\n");
                return;

            }
            nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, kfwprepmss->dg_size, 0);
            NETLINK_CB(skb_out).dst_group = 0; /* not in mcast group */

            printk(KERN_INFO
            "%d\n", i);


            memcpy(nlmsg_data(nlh), (void *) &kmc_i.datas + i * sizeof(data_t), kfwprepmss->dg_size);
            printk(KERN_INFO
            "copying data %s\n", kmc_i.datas[i].name);
            printk(KERN_INFO
            "copying curr %d\n", kmc_i.datas[i].current_rules);


            res = nlmsg_unicast(nl_sk, skb_out, pid);
//
            printk(KERN_INFO
            "sending datas_cache header to userspace\n");
            if (res < 0)
                printk(KERN_INFO
            "Error while sending bak to user\n");
        }


        kfree(kfwprepmss);


    }


        // show policies_cache
    else if (kfwpmss->type == 0b00001111) {
        kfwprepmss = (kfwp_reply_t *) kmalloc(4, GFP_KERNEL);

        kfwprepmss->status = 0b00000000;
        kfwprepmss->dg_size = 12; //TODO‌ make this a macro
        kfwprepmss->dg_cnt = kmc_i.current_kfw_policies;

        printk(KERN_INFO
        "cnt{%d}\n", kfwprepmss->dg_cnt);
        printk(KERN_INFO
        "dgsize{%d}\n", kfwprepmss->dg_size);



//                    memcpy(kfwprepmss->payload, &kmc_i.datas_cache[kmc_i.AUX_functions_returns], sizeof(data_t));
//                    printk(KERN_INFO
//                    "inja2\n");

        memcpy(nlmsg_data(nlh), kfwprepmss, 4);
        res = nlmsg_unicast(nl_sk, skb_out, pid);
        printk(KERN_INFO
        "inja3\n");

        if (res < 0)
            printk(KERN_INFO
        "Error while sending bak to user\n");


//
        int i = 0;
        for (i = 0; i < kfwprepmss->dg_cnt; i++) {

            skb_out = nlmsg_new(kfwprepmss->dg_size, 0);
            if (!skb_out) {

                printk(KERN_ERR
                "Failed to allocate new skb\n");
                return;

            }
            nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, kfwprepmss->dg_size, 0);
            NETLINK_CB(skb_out).dst_group = 0; /* not in mcast group */

            printk(KERN_INFO
            "%d\n", i);

            printk(KERN_INFO
            "copying policy %s\n", kmc_i.policies[i].name);
            printk(KERN_INFO
            "copying curr %d\n", kmc_i.policies[i].current_data_actions);

            memcpy(nlmsg_data(nlh), (void *) &kmc_i.policies + i * sizeof(policy_t), kfwprepmss->dg_size);


            res = nlmsg_unicast(nl_sk, skb_out, pid);
//
            printk(KERN_INFO
            "sending policies_cache headers to userspace\n");
            if (res < 0)
                printk(KERN_INFO
            "Error while sending bak to user\n");
        }


        kfree(kfwprepmss);


    }


        // service policy command
    else if (kfwpmss->type == 0b00000100) {

        // setting needed vaiables
        memset(kmc_i.AUX_policy_name, 0, MAX_LEN_POLICY_NAME);
        memset(kmc_i.AUX_interface_name, 0, MAX_LEN_INTERFACE_NAME);
        memset(kmc_i.AUX_policy_direction, 0, MAX_LEN_POLICY_DIRECTION);

        // copying policy_name from kfwp request

        strcpy(kmc_i.AUX_policy_name, kfwpmss->arg1);
        strcpy(kmc_i.AUX_interface_name, kfwpmss->arg2);
        strcpy(kmc_i.AUX_policy_direction, kfwpmss->context);

        printk(KERN_INFO
        "service policy command issued %s\n", kmc_i.AUX_policy_name);
        printk(KERN_INFO
        "service policy command issued %s\n", kmc_i.AUX_interface_name);
        printk(KERN_INFO
        "service policy command issued %s\n", kmc_i.AUX_policy_direction);

        kmc_i.AUX_functions_returns = get_index_of_policy_in_policies(&kmc_i, kmc_i.AUX_policy_name);

        if (kmc_i.AUX_functions_returns == -1) {

            kfwprepmss = (kfwp_reply_t *) kmalloc(4, GFP_KERNEL);


            //send reply back to userspace
            kfwprepmss->status = 0b00000001;
            kfwprepmss->dg_cnt = 0;
            memcpy(nlmsg_data(nlh), kfwprepmss, 4);
            res = nlmsg_unicast(nl_sk, skb_out, pid);
            printk(KERN_INFO
            "raft policy nabud\n");

            if (res < 0)
                printk(KERN_INFO
            "Error while sending bak to user\n");
            kfree(kfwprepmss);

        } else {

            if (strncmp(kmc_i.AUX_policy_direction, "in", 2) == 0) {
                kmc_i.AUX_functions_returns = get_index_of_policyint_in_ingress(&ingress_policies,
                                                                                kmc_i.AUX_interface_name);

                if (kmc_i.AUX_functions_returns == -1) {
                    // we have not had defined a policy on the interface
                    // so we create the new one

                    memset(&ingress_policies.policyWithInterfaces[ingress_policies.current_ingress_policies], 0,
                           sizeof(policy_with_int_t));
                    strcpy(ingress_policies.policyWithInterfaces[ingress_policies.current_ingress_policies].policy_name,
                           kmc_i.AUX_policy_name);
                    strcpy(ingress_policies.policyWithInterfaces[ingress_policies.current_ingress_policies].interface_name,
                           kmc_i.AUX_interface_name);
                    ingress_policies.current_ingress_policies++;

                    kfwprepmss = (kfwp_reply_t *) kmalloc(4, GFP_KERNEL);


                    //send reply back to userspace
                    // saying error of not existance of the data
                    kfwprepmss->status = 0b00000000;
                    kfwprepmss->dg_cnt = 0;
                    memcpy(nlmsg_data(nlh), kfwprepmss, 4);
                    res = nlmsg_unicast(nl_sk, skb_out, pid);
                    printk(KERN_INFO
                    "ingress policy  created \n");

                    if (res < 0)
                        printk(KERN_INFO
                    "Error while sending bak to user\n");
                    kfree(kfwprepmss);


                    printk(KERN_INFO
                    "new ingress policy was created\n");
                } else {

                    // we already have defined a policy on the interface
                    // we want to update it we new/old policy.i said old
                    // becuase i dont want to check whether the old and the new one
                    // are same or not

                    // we clear the previous plocy name
                    memset(&ingress_policies.policyWithInterfaces[kmc_i.AUX_functions_returns], 0, MAX_LEN_POLICY_NAME);
                    strcpy(ingress_policies.policyWithInterfaces[kmc_i.AUX_functions_returns].policy_name,
                           kmc_i.AUX_policy_name);

                    kfwprepmss = (kfwp_reply_t *) kmalloc(4, GFP_KERNEL);


                    //send reply back to userspace
                    // saying error of not existance of the data
                    kfwprepmss->status = 0b10000000;
                    kfwprepmss->dg_cnt = 0;
                    memcpy(nlmsg_data(nlh), kfwprepmss, 4);
                    res = nlmsg_unicast(nl_sk, skb_out, pid);
                    printk(KERN_INFO
                    "ingress policy  existed and updated \n");

                    if (res < 0)
                        printk(KERN_INFO
                    "Error while sending bak to user\n");
                    kfree(kfwprepmss);

                }
            } else {
                kmc_i.AUX_functions_returns = get_index_of_policyint_in_egress(&egress_policies,
                                                                               kmc_i.AUX_interface_name);
                if (kmc_i.AUX_functions_returns == -1) {

                    memset(&egress_policies.policyWithInterfaces[egress_policies.current_egress_policies], 0,
                           sizeof(policy_with_int_t));
                    strcpy(egress_policies.policyWithInterfaces[egress_policies.current_egress_policies].policy_name,
                           kmc_i.AUX_policy_name);
                    strcpy(egress_policies.policyWithInterfaces[egress_policies.current_egress_policies].interface_name,
                           kmc_i.AUX_interface_name);
                    egress_policies.current_egress_policies++;

                    kfwprepmss = (kfwp_reply_t *) kmalloc(4, GFP_KERNEL);


                    //send reply back to userspace
                    // saying error of not existance of the data
                    kfwprepmss->status = 0b00000000;
                    kfwprepmss->dg_cnt = 0;
                    memcpy(nlmsg_data(nlh), kfwprepmss, 4);
                    res = nlmsg_unicast(nl_sk, skb_out, pid);
                    printk(KERN_INFO
                    "egress policy  created \n");

                    if (res < 0)
                        printk(KERN_INFO
                    "Error while sending bak to user\n");
                    kfree(kfwprepmss);


                    printk(KERN_INFO
                    "new egress policy was created\n");

                } else {

                    // we already have defined a policy on the interface
                    // we want to update it we new/old policy.i said old
                    // becuase i dont want to check whether the old and the new one
                    // are same or not

                    // we clear the previous plocy name
                    memset(&egress_policies.policyWithInterfaces[kmc_i.AUX_functions_returns], 0, MAX_LEN_POLICY_NAME);
                    strcpy(egress_policies.policyWithInterfaces[kmc_i.AUX_functions_returns].policy_name,
                           kmc_i.AUX_policy_name);


                    kfwprepmss = (kfwp_reply_t *) kmalloc(4, GFP_KERNEL);



                    //send reply back to userspace
                    // saying error of not existance of the data
                    kfwprepmss->status = 0b10000000;
                    kfwprepmss->dg_cnt = 0;
                    memcpy(nlmsg_data(nlh), kfwprepmss, 4);
                    res = nlmsg_unicast(nl_sk, skb_out, pid);
                    printk(KERN_INFO
                    "egress policy existed and update \n");

                    if (res < 0)
                        printk(KERN_INFO
                    "Error while sending bak to user\n");
                    kfree(kfwprepmss);

                }
            }


        }


    }



        // no service policy command
    else if (kfwpmss->type == 0b10000100) {

        // setting needed vaiables
        memset(kmc_i.AUX_policy_name, 0, MAX_LEN_POLICY_NAME);
        memset(kmc_i.AUX_interface_name, 0, MAX_LEN_INTERFACE_NAME);
        memset(kmc_i.AUX_policy_direction, 0, MAX_LEN_POLICY_DIRECTION);

        // copying policy_name from kfwp request

        strcpy(kmc_i.AUX_policy_name, kfwpmss->arg1);
        strcpy(kmc_i.AUX_interface_name, kfwpmss->arg2);
        strcpy(kmc_i.AUX_policy_direction, kfwpmss->context);

        printk(KERN_INFO
        "service policy command issued %s\n", kmc_i.AUX_policy_name);
        printk(KERN_INFO
        "service policy command issued %s\n", kmc_i.AUX_interface_name);
        printk(KERN_INFO
        "service policy command issued %s\n", kmc_i.AUX_policy_direction);

        kmc_i.AUX_functions_returns = get_index_of_policy_in_policies(&kmc_i, kmc_i.AUX_policy_name);

        if (kmc_i.AUX_functions_returns == -1) {

            kfwprepmss = (kfwp_reply_t *) kmalloc(4, GFP_KERNEL);


            //send reply back to userspace
            kfwprepmss->status = 0b00000001;
            kfwprepmss->dg_cnt = 0;
            memcpy(nlmsg_data(nlh), kfwprepmss, 4);
            res = nlmsg_unicast(nl_sk, skb_out, pid);
            printk(KERN_INFO
            "raft policy nabud\n");

            if (res < 0)
                printk(KERN_INFO
            "Error while sending bak to user\n");
            kfree(kfwprepmss);

        } else {

            // TODO‌ make this code better
            if (strcmp(kmc_i.AUX_policy_direction, "out") == 0) {
                printk(KERN_INFO
                "umade to out\n");


                kmc_i.AUX_functions_returns = get_index_of_policyint_in_egress(&egress_policies,
                                                                               kmc_i.AUX_interface_name);

                if (kmc_i.AUX_functions_returns != -1) {
                    printk(KERN_INFO
                    "vujud dasht\n");


                    // check whether tha policy_name user entered , matched the policy name in policywithint
                    // structure.i dont want user to be able to delete a service with policy that exist
                    // in kfw but not have been set on the interface

                    if (strncmp(egress_policies.policyWithInterfaces[kmc_i.AUX_functions_returns].policy_name,
                                kmc_i.AUX_policy_name, strlen(kmc_i.AUX_policy_name)) != 0) {

                        // send reply to user and tell him/her that this policy exsit on kfw but has not set
                        // on the interface anymore
                        kfwprepmss = (kfwp_reply_t *) kmalloc(4, GFP_KERNEL);

                        //send reply back to userspace
                        // saying error of not existance of the data
                        kfwprepmss->status = 0b00000010;
                        kfwprepmss->dg_cnt = 0;
                        memcpy(nlmsg_data(nlh), kfwprepmss, 4);
                        res = nlmsg_unicast(nl_sk, skb_out, pid);
                        printk(KERN_INFO
                        "policy_name does exist on kfw but has not been set on this interface on this directtion \n");

                        if (res < 0)
                            printk(KERN_INFO
                        "Error while sending bak to user\n");
                        kfree(kfwprepmss);

                    } else {

                        // Deletion of policy is like before
                        if (kmc_i.AUX_functions_returns == egress_policies.current_egress_policies - 1) {
                            if (egress_policies.current_egress_policies - 1 != -1)
                                egress_policies.current_egress_policies--;
                        } else {
                            kmc_i.AUX_functions_returns++;
                            while (kmc_i.AUX_functions_returns <= egress_policies.current_egress_policies - 1) {
                                memcpy(&egress_policies.policyWithInterfaces[kmc_i.AUX_functions_returns - 1],
                                       &egress_policies.policyWithInterfaces[kmc_i.AUX_functions_returns],
                                       sizeof(policy_with_int_t));
                                kmc_i.AUX_functions_returns++;
                            }
                            // update total number of policy_with_int
                            egress_policies.current_egress_policies--;
                        }

                        // send reply to user and tell deletion was successful
                        kfwprepmss = (kfwp_reply_t *) kmalloc(4, GFP_KERNEL);

                        kfwprepmss->status = 0b00000000;
                        kfwprepmss->dg_cnt = 0;
                        memcpy(nlmsg_data(nlh), kfwprepmss, 4);
                        res = nlmsg_unicast(nl_sk, skb_out, pid);
                        printk(KERN_INFO
                        "policy on egress deleted successfully \n");

                        if (res < 0)
                            printk(KERN_INFO
                        "Error while sending bak to user\n");
                        kfree(kfwprepmss);


                    }

                } else {
                    kfwprepmss = (kfwp_reply_t *) kmalloc(4, GFP_KERNEL);

                    // send reply back to user telling no policy has been set on
                    // the interface specified
                    kfwprepmss->status = 0b00000011;
                    kfwprepmss->dg_cnt = 0;
                    memcpy(nlmsg_data(nlh), kfwprepmss, 4);
                    res = nlmsg_unicast(nl_sk, skb_out, pid);
                    printk(KERN_INFO
                    "no policy has been set on the interface egress \n");

                    if (res < 0)
                        printk(KERN_INFO
                    "Error while sending bak to user\n");
                    kfree(kfwprepmss);


                }

            } else {

                printk(KERN_INFO
                "umade to in\n");


                kmc_i.AUX_functions_returns = get_index_of_policyint_in_ingress(&ingress_policies,
                                                                                kmc_i.AUX_interface_name);

                if (kmc_i.AUX_functions_returns != -1) {
                    printk(KERN_INFO
                    "vujud dasht\n");


                    // check whether tha policy_name user entered , matched the policy name in policywithint
                    // structure.i dont want user to be able to delete a service with policy that exist
                    // in kfw but not have been set on the interface

                    if (strncmp(ingress_policies.policyWithInterfaces[kmc_i.AUX_functions_returns].policy_name,
                                kmc_i.AUX_policy_name, strlen(kmc_i.AUX_policy_name)) != 0) {

                        // send reply to user and tell him/her that this policy exsit on kfw but has not set
                        // on the interface anymore
                        kfwprepmss = (kfwp_reply_t *) kmalloc(4, GFP_KERNEL);

                        //send reply back to userspace
                        // saying error of not existance of the data
                        kfwprepmss->status = 0b00000010;
                        kfwprepmss->dg_cnt = 0;
                        memcpy(nlmsg_data(nlh), kfwprepmss, 4);
                        res = nlmsg_unicast(nl_sk, skb_out, pid);
                        printk(KERN_INFO
                        "policy_name does exist on kfw but has not been set on this interface on this directtion \n");

                        if (res < 0)
                            printk(KERN_INFO
                        "Error while sending bak to user\n");
                        kfree(kfwprepmss);

                    } else {

                        if (kmc_i.AUX_functions_returns != -1) {
                            // Deletion policy is like before
                            if (kmc_i.AUX_functions_returns == ingress_policies.current_ingress_policies - 1) {
                                if (ingress_policies.current_ingress_policies - 1 != -1)
                                    ingress_policies.current_ingress_policies--;
                            } else {
                                kmc_i.AUX_functions_returns++;
                                while (kmc_i.AUX_functions_returns <= ingress_policies.current_ingress_policies - 1) {
                                    memcpy(&ingress_policies.policyWithInterfaces[kmc_i.AUX_functions_returns - 1],
                                           &ingress_policies.policyWithInterfaces[kmc_i.AUX_functions_returns],
                                           sizeof(policy_with_int_t));
                                    kmc_i.AUX_functions_returns++;
                                }
                                // update total number of policy_with_int
                                ingress_policies.current_ingress_policies--;

                            }


                            // send reply to user and tell deletion was successful
                            kfwprepmss = (kfwp_reply_t *) kmalloc(4, GFP_KERNEL);

                            //send reply back to userspace
                            // saying error of not existance of the data
                            kfwprepmss->status = 0b00000000;
                            kfwprepmss->dg_cnt = 0;
                            memcpy(nlmsg_data(nlh), kfwprepmss, 4);
                            res = nlmsg_unicast(nl_sk, skb_out, pid);
                            printk(KERN_INFO
                            "policy on ingress deleted successfully \n");

                            if (res < 0)
                                printk(KERN_INFO
                            "Error while sending bak to user\n");
                            kfree(kfwprepmss);


                        }

                    }
                } else {
                    // send reply back to user telling no policy has been set on
                    // the interface specified
                    kfwprepmss = (kfwp_reply_t *) kmalloc(4, GFP_KERNEL);


                    kfwprepmss->status = 0b00000011;
                    kfwprepmss->dg_cnt = 0;
                    memcpy(nlmsg_data(nlh), kfwprepmss, 4);
                    res = nlmsg_unicast(nl_sk, skb_out, pid);
                    printk(KERN_INFO
                    "no policy has been set on the interface ingress \n");

                    if (res < 0)
                        printk(KERN_INFO
                    "Error while sending bak to user\n");
                    kfree(kfwprepmss);


                }
            }
        }
    }




        // update ingress policies_cache cache
    else if (kfwpmss->type == 0b00001000) {
        kfwprepmss = (kfwp_reply_t *) kmalloc(4, GFP_KERNEL);

        kfwprepmss->status = 0b00000000;
        kfwprepmss->dg_size = sizeof(policy_with_int_t); //TODO‌ make this a macro
        kfwprepmss->dg_cnt = ingress_policies.current_ingress_policies;

        printk(KERN_INFO
        "cnt{%d}\n", kfwprepmss->dg_cnt);
        printk(KERN_INFO
        "dgsize{%d}\n", kfwprepmss->dg_size);


        memcpy(nlmsg_data(nlh), kfwprepmss, 4);
        res = nlmsg_unicast(nl_sk, skb_out, pid);
        printk(KERN_INFO
        "ingress dare mire\n");

        if (res < 0)
            printk(KERN_INFO
        "Error while sending bak to user\n");


        int i = 0;
        for (i = 0; i < kfwprepmss->dg_cnt; i++) {

            skb_out = nlmsg_new(kfwprepmss->dg_size, 0);
            if (!skb_out) {

                printk(KERN_ERR
                "Failed to allocate new skb\n");
                return;

            }
            nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, kfwprepmss->dg_size, 0);
            NETLINK_CB(skb_out).dst_group = 0; /* not in mcast group */

            printk(KERN_INFO
            "%d\n", i);

            memcpy(nlmsg_data(nlh), (void *) &ingress_policies.policyWithInterfaces + i * sizeof(policy_with_int_t),
                   kfwprepmss->dg_size);


            res = nlmsg_unicast(nl_sk, skb_out, pid);
//
            printk(KERN_INFO
            "sending ingress payload to userspace\n");
            if (res < 0)
                printk(KERN_INFO
            "Error while sending bak to user\n");
        }


        kfree(kfwprepmss);


    }



    // update egress policies_cache cache
    else if (kfwpmss->type == 0b00001001){
        kfwprepmss = (kfwp_reply_t *) kmalloc(4, GFP_KERNEL);

        kfwprepmss->status = 0b00000000;
        kfwprepmss->dg_size=sizeof(policy_with_int_t); //TODO‌ make this a macro
        kfwprepmss->dg_cnt =egress_policies.current_egress_policies;

        printk(KERN_INFO"cnt{%d}\n", kfwprepmss->dg_cnt);
        printk(KERN_INFO"dgsize{%d}\n", kfwprepmss->dg_size);



        memcpy(nlmsg_data(nlh), kfwprepmss, 4);
        res = nlmsg_unicast(nl_sk, skb_out, pid);
        printk(KERN_INFO "egress dare mire\n");

        if (res < 0)
            printk(KERN_INFO"Error while sending bak to user\n");


        int i=0;
        for(i=0;i<kfwprepmss->dg_cnt;i++){

            skb_out = nlmsg_new(kfwprepmss->dg_size,0);
            if(!skb_out)
            {
                printk(KERN_ERR "Failed to allocate new skb\n");
                return;
            }

            nlh=nlmsg_put(skb_out,0,0,NLMSG_DONE,kfwprepmss->dg_size,0);
            NETLINK_CB(skb_out).dst_group = 0; /* not in mcast group */

            printk(KERN_INFO"%d\n",i);


            memcpy(nlmsg_data(nlh), (void *)&egress_policies.policyWithInterfaces + i * sizeof(policy_with_int_t),kfwprepmss->dg_size);



            res = nlmsg_unicast(nl_sk, skb_out, pid);
//
            printk(KERN_INFO"sending egress payload to userspace\n");
            if (res < 0)
                printk(KERN_INFO"Error while sending bak to user\n");
        }


        kfree(kfwprepmss);




    }
}

static int __init hello_init(void) {


    kmc_i.current_kfw_policies=0;
    kmc_i.current_kfw_datas=0;



    printk("Entering: %s\n",__FUNCTION__);
//This is for 3.6 kernels and above.
    struct netlink_kernel_cfg cfg = {
            .input = hello_nl_recv_msg,
    };

    nl_sk = netlink_kernel_create(&init_net, NETLINK_USER, &cfg);
//nl_sk = netlink_kernel_create(&init_net, NETLINK_USER, 0, hello_nl_recv_msg,NULL,THIS_MODULE);
    if(!nl_sk)
    {

        printk(KERN_ALERT "Error creating socket.\n");
        return -10;

    }



    return 0;
}

static void __exit hello_exit(void) {

    printk(KERN_INFO "exiting hello module\n");
    netlink_kernel_release(nl_sk);
}

module_init(hello_init);
module_exit(hello_exit);

MODULE_LICENSE("GPL");

