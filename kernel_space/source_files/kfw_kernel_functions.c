/*
 *
 *  THIS FILE CONTAINS KERNEL MODULE MAIN FUNCTIONS
 *
 *
 *
 *  Written By :  Kiarash Sedghi
 *
 *
 * */

#include <linux/module.h>
#include "linux/kfw_kernel.h"
#include "linux/kfw_kernel_functions.h"


onebyte_np_t get_index_of_data_in_datas(kmc_controles_t *kmci,onebyte_p_t *data_name){


    int i=0;
    for( i=0;i<kmci->current_kfw_datas;i++){
        printk(KERN_ERR "len<<%s>>\n",(kmci->datas[i].name));
        printk(KERN_ERR "len2<<%s>>\n",(data_name));

        if(memcmp(kmci->datas[i].name,data_name,strlen(data_name))==0){
            printk(KERN_ERR "yeksan\n");

            return i;
        }
    }
    return -1;
}

onebyte_np_t get_index_of_rule_in_rules(data_t *data_st ,onebyte_p_t *rule_type ){
    int i=0;
    for(i=0;i<data_st->current_rules;i++){
        if (strncmp(data_st->rules[i].type, rule_type, strlen(rule_type)) == 0)
            return i;
    }
    return -1;


}

onebyte_np_t get_index_of_policy_in_policies(kmc_controles_t *kmci,onebyte_p_t *policy_name){


    int i=0;
    for(i=0;i<kmci->current_kfw_policies;i++) {
        if (strncmp(kmci->policies[i].name, policy_name, strlen(policy_name)) == 0) {
            return i;
        }

    }
    return -1;

}

onebyte_np_t get_index_of_datawithaction_in_policies(policy_t *policy , onebyte_p_t *data_name){
    int i;
    for( i=0;i<policy->current_data_actions;i++){
        if(strncmp(policy->data_with_actions[i].data_name,data_name,strlen(data_name))==0)
            return i;
    }
    return -1;
}

onebyte_np_t check_policy_dependeny_on_data(kmc_controles_t *kmci,onebyte_p_t *data_name){
    int i=0;
    int j=0;
    for(i=0;i<kmci->current_kfw_policies;i++){
        for(j=0;j<kmci->policies[i].current_data_actions;j++){
            if(strncmp(kmci->policies[i].data_with_actions[j].data_name,data_name,strlen(data_name))==0)
                return i;
        }
    }
    return -1;

}

onebyte_np_t check_ingress_dependency_on_policy(ingress_policies_t *ingress_policies,onebyte_p_t *policy_name){
    int i=0;
    for(i=0;i<ingress_policies->current_ingress_policies;i++){
        if(strncmp(ingress_policies->policyWithInterfaces[i].policy_name,policy_name,strlen(policy_name))==0)
            return i;
    }
    return -1;
}

onebyte_np_t check_egress_dependency_on_policy(egress_policies_t *egress_policies,onebyte_p_t *policy_name){
    int i=0;
    for(i=0;i<egress_policies->current_egress_policies;i++){
        if(strncmp(egress_policies->policyWithInterfaces[i].policy_name,policy_name,strlen(policy_name))==0)
            return i;
    }
    return -1;
}

onebyte_np_t get_index_of_policyint_in_egress(egress_policies_t *egressPolicies ,onebyte_p_t*interface_name){

    // we search in egress policies_cache based on the interface_name not policy_name
    // Th reason is we want to find out whether we have defined a policy on the interface or not
    // if not , we create a new egress entry and if yes , we update that policy if it was changed
    // because we can only set one policy on each interface on each direction
    int i=0;
    for(i=0;i<egressPolicies->current_egress_policies;i++){
        if(strncmp(egressPolicies->policyWithInterfaces[i].interface_name,interface_name,strlen(interface_name))==0)
            return i;
    }
    return -1;

}

onebyte_np_t get_index_of_policyint_in_ingress(ingress_policies_t *ingressPolicies ,onebyte_p_t *interface_name){

    // we search in ingress policies_cache based on the interface_name not policy_name
    // Th reason is we want to find out whether we have defined a policy on the interface or not
    // if not , we create a new egress entry and if yes , we update that policy if it was changed
    // because we can only set one policy on each interface on each direction

    int i=0;
    for( i=0;i<ingressPolicies->current_ingress_policies;i++){
        if(strncmp(ingressPolicies->policyWithInterfaces[i].interface_name,interface_name,strlen(interface_name))==0)
            return i;
    }
    return -1;

}



void send_kfwp_reply(onebyte_p_t status , onebyte_p_t page_cnt, twobyte_p_t page_size, struct nlmsghdr *nlh, int pid, struct sk_buff *skb_out){
    /*
     * This function sends reply to userspace program
     *
     * */

    kmc_i.kfwprepmss = (kfwp_reply_t *) kmalloc(4, GFP_KERNEL);


    //send reply back to userspace
    kmc_i.kfwprepmss->status = status;
    kmc_i.kfwprepmss->page_cnt = page_cnt;
    kmc_i.kfwprepmss->page_size=page_size;
    memcpy(nlmsg_data(nlh), kmc_i.kfwprepmss, 4);

    if(nlmsg_unicast(kmc_i.nl_sk, skb_out, pid)>=0)
        printk(KERN_INFO"reply sent \n");
    else
    printk(KERN_INFO"Error while sending reply to to user\n");

    kfree(kmc_i.kfwprepmss);

}


void set_ip_address_wildcard_mask(onebyte_p_t *rule_value){
    /*
     * This function extracts IP and WM from rule_value and based on the
     * values , it will set kmc_i.ip_addr and kmc_i.wildcard_mask
     *
     * */
    kmc_i.AUX_str_ptr=rule_value;
    kmc_i.negation_flag=0;
    if(*rule_value==(int)'!'){
        kmc_i.AUX_str_ptr++;
        kmc_i.negation_flag=1;
    }
    kmc_i.AUX_str_ptr_temp=kmc_i.AUX_str_ptr;

    while(*kmc_i.AUX_str_ptr && *kmc_i.AUX_str_ptr!=(int)'/')
        kmc_i.AUX_str_ptr++;
    memset(kmc_i.ip_addr,0,16);

    memcpy(kmc_i.ip_addr,kmc_i.AUX_str_ptr_temp,kmc_i.AUX_str_ptr-kmc_i.AUX_str_ptr_temp);

    memset(kmc_i.wildcard_mask,0,16);
    // if user has not specified wildcard mask
    // set it to 255.255.255.255
    if(*kmc_i.AUX_str_ptr==0)
        memcpy(kmc_i.wildcard_mask,"0.0.0.0",7);
    else{
        kmc_i.AUX_str_ptr++;
        kmc_i.AUX_str_ptr_temp=kmc_i.AUX_str_ptr;
        while(*kmc_i.AUX_str_ptr)
            kmc_i.AUX_str_ptr++;
        memcpy(kmc_i.wildcard_mask,kmc_i.AUX_str_ptr_temp,kmc_i.AUX_str_ptr-kmc_i.AUX_str_ptr_temp);
    }

}


onebyte_p_t is_port_in_range(int *port_ranges, twobyte_p_t port_number, onebyte_p_t negation_bit){
    /*
     *
     * This function checks whether port_number is in range of ports stored in kmc_i.port_number_array
     *
     * */
    int i=0;
    for(i=0;i<=50;i++)
        printk(KERN_INFO "%d\n",*(kmc_i.port_number_array_start+i));

    while(*port_ranges!=-2){
        if(*(port_ranges+1)==-1) {
            if (kmc_i.port_number >= *(port_ranges) && kmc_i.port_number <= *(port_ranges + 2)) {
                return 1 | negation_bit;
            }
            else
                port_ranges += 3;
        }
        else{

            if(*port_ranges==kmc_i.port_number){
                return 1 | negation_bit;
            }
            port_ranges++;
        }
    }
    return 0 | negation_bit;

}



void fill_port_arr(onebyte_p_t *rule_value){
    /*
     * This function extracts port numbers and port ranges from rule_value
     * and set them in kmc_i.port_number_array
     * */

    kmc_i.port_number_array=kmc_i.port_number_array_start;
    //inititalize the array with -2
    int i;
    for(i=0;i<50;i++) {
        *(kmc_i.port_number_array+i) = -2;
    }
    kmc_i.port_number_ptr=rule_value;

    // if the not used with the rule,skip kmc_i.port_number_ptr ptr by 1
    if(*kmc_i.port_number_ptr==(int)'!')
        kmc_i.port_number_ptr++;

    kmc_i.port_number=0;
    while(*kmc_i.port_number_ptr){
        if(*kmc_i.port_number_ptr==(onebyte_p_t)'-'){
            *kmc_i.port_number_array=-1;
            kmc_i.port_number_array++;
            kmc_i.port_number_ptr++;
        }
        else if(*kmc_i.port_number_ptr!=(onebyte_p_t)','){
            kmc_i.port_number_ptr_temp=kmc_i.port_number_ptr;
            while(*kmc_i.port_number_ptr_temp && *kmc_i.port_number_ptr_temp!=(onebyte_p_t)'-' && *kmc_i.port_number_ptr_temp!=(onebyte_p_t)',')
                kmc_i.port_number_ptr_temp++;
            kmc_i.port_number=0;
            while(kmc_i.port_number_ptr!=kmc_i.port_number_ptr_temp){
                kmc_i.port_number+=(*kmc_i.port_number_ptr-48)*power(10,kmc_i.port_number_ptr_temp-kmc_i.port_number_ptr-1);
                kmc_i.port_number_ptr++;
            }
            *kmc_i.port_number_array=kmc_i.port_number;
            kmc_i.port_number_array++;

        } else{
            kmc_i.port_number_ptr++;
        }
    }


}


int power(int x,int p){
    int q=1;
    int i;
    for(i=0;i<p;i++)
        q*=x;
    return q;
}

unsigned int inet_addr(char *str)
{
    int a, b, c, d;
    char arr[4];
    sscanf(str, "%d.%d.%d.%d", &a, &b, &c, &d);
    arr[0] = a; arr[1] = b; arr[2] = c; arr[3] = d;
    return *(unsigned int *)arr;
}



onebyte_p_t rule_match(onebyte_p_t *rule_type,onebyte_p_t *rule_value,struct sk_buff* skb) {
    /*
     * This function takes traffic and checks whether it matches the rule specified by
     * rule_type and rule_value or not
     *
     * */
    if (strcmp(rule_type, "dudp") == 0 || strcmp(rule_type, "sudp") == 0) {
        if (kmc_i.iph_t->protocol == 17) {
            kmc_i.udph_t = udp_hdr(skb);
            fill_port_arr(rule_value);
            if (*rule_value == (int) '!') {
                // checking the negation form of the rule
                if (strcmp(rule_type, "dudp") == 0)
                    return is_port_in_range(kmc_i.port_number_array_start, ntohs(kmc_i.udph_t->dest), 1);
                // check for source udp kmc_i.port_number
                return is_port_in_range(kmc_i.port_number_array_start, ntohs(kmc_i.udph_t->source), 1);
            } else {
                // checking the positive form of the rule
                if (strcmp(rule_type, "dudp") == 0)
                    return is_port_in_range(kmc_i.port_number_array_start, ntohs(kmc_i.udph_t->dest), 0);
                // check for source udp kmc_i.port_number
                return is_port_in_range(kmc_i.port_number_array_start, ntohs(kmc_i.udph_t->source), 0);
            }
        }
        // if the protocol was not udp , return 0 meaning not matched
        return 0;
    }

    else if (strcmp(rule_type, "dtcp") == 0 || strcmp(rule_type, "stcp") == 0) {
        if (kmc_i.iph_t->protocol == 6) {
            kmc_i.tcph_t = tcp_hdr(skb);
            fill_port_arr(rule_value);
            if (*rule_value == (int) '!') {
                // checking the negation form of the rule
                if (strcmp(rule_type, "dtcp") == 0)
                    return is_port_in_range(kmc_i.port_number_array_start, ntohs(kmc_i.tcph_t->dest), 1);
                // check for source udp kmc_i.port_number
                return is_port_in_range(kmc_i.port_number_array_start, ntohs(kmc_i.tcph_t->source), 1);
            } else {
                // checking the positive form of the rule
                if (strcmp(rule_type, "dtcp") == 0)
                    return is_port_in_range(kmc_i.port_number_array_start, ntohs(kmc_i.tcph_t->dest), 0);
                // check for source udp kmc_i.port_number
                return is_port_in_range(kmc_i.port_number_array_start, ntohs(kmc_i.tcph_t->source), 0);
            }
        }
        // if the protocol was not tcp , return 0 meaning not matched
        return 0;
    }

    else if(strcmp(rule_type,"proto")==0){
        kmc_i.AUX_str_ptr=rule_value;
        kmc_i.negation_flag=0;
        if(*rule_value==(int)'!') {
            kmc_i.AUX_str_ptr++;
            // set negation variable to 1
            kmc_i.negation_flag=1;
        }
        // parsing rule value
        while(*kmc_i.AUX_str_ptr){
            if(*kmc_i.AUX_str_ptr!=(int)','){
                kmc_i.AUX_str_ptr_temp=kmc_i.AUX_str_ptr;
                while(*kmc_i.AUX_str_ptr && *kmc_i.AUX_str_ptr!=(int)',')
                    kmc_i.AUX_str_ptr++;
                memset(kmc_i.protocol_name,0,8);
                memcpy(kmc_i.protocol_name,kmc_i.AUX_str_ptr_temp,kmc_i.AUX_str_ptr-kmc_i.AUX_str_ptr_temp);
                //kmc_i.protocol_name check
                if(strcmp(kmc_i.protocol_name,"tcp")==0){
                    //checking if the protocol was tcp
                    if(kmc_i.iph_t->protocol==6)
                        return 1|kmc_i.negation_flag;
                    // return 0|kmc_i.negation_flag;
                }

                else if(strcmp(kmc_i.protocol_name,"udp")==0){
                    if(kmc_i.iph_t->protocol==17)
                        return 1|kmc_i.negation_flag;
                    // return 0|kmc_i.negation_flag;
                }

                else if(strcmp(kmc_i.protocol_name,"dns")==0 || strcmp(kmc_i.protocol_name,"dns/udp")==0){
                    if(kmc_i.iph_t->protocol==17){
                        kmc_i.udph_t = udp_hdr(skb);

                        // including both server and client
                        if(ntohs(kmc_i.udph_t->dest)==53 || ntohs(kmc_i.udph_t->source)==53)
                            return 1|kmc_i.negation_flag;
                        //return 0|kmc_i.negation_flag;
                    }
                    //   return 0|kmc_i.negation_flag;
                }

                else if(strcmp(kmc_i.protocol_name,"dns/tcp")==0){
                    if(kmc_i.iph_t->protocol==6){
                        kmc_i.tcph_t = tcp_hdr(skb);
                        // including both server and client
                        if(ntohs(kmc_i.tcph_t->dest)==53 || ntohs(kmc_i.tcph_t->source)==53)
                            return 1|kmc_i.negation_flag;
                        //return 0|kmc_i.negation_flag;
                    }
                    //return 0|kmc_i.negation_flag;
                }

                else if(strcmp(kmc_i.protocol_name,"dhcp")==0){
                    if(kmc_i.iph_t->protocol==17){
                        //check both dst_port and src_prt
                        kmc_i.udph_t = udp_hdr(skb);

                        // including both server and client
                        if(ntohs(kmc_i.udph_t->dest)==67 || ntohs(kmc_i.udph_t->dest)==68 || ntohs(kmc_i.udph_t->source)==67 || ntohs(kmc_i.udph_t->source)==68)
                            return 1|kmc_i.negation_flag;
                    }
                }

                else if(strcmp(kmc_i.protocol_name,"icmp")==0){

                    if(kmc_i.iph_t->protocol==1)
                        return 1|kmc_i.negation_flag;
                }

                else if(strcmp(kmc_i.protocol_name,"igmp")==0){
                    if(kmc_i.iph_t->protocol==2)
                        return 1|kmc_i.negation_flag;
                }

                else if(strcmp(kmc_i.protocol_name,"ftp")==0){
                    if(kmc_i.iph_t->protocol==6){
                        kmc_i.tcph_t=tcp_hdr(skb);
                        // include both server and client
                        if(kmc_i.tcph_t->dest==20 || kmc_i.tcph_t->dest==21 || kmc_i.tcph_t->source==20 || kmc_i.tcph_t->source==21)
                            return 1|kmc_i.negation_flag;

                    }
                }

                else if(strcmp(kmc_i.protocol_name,"telnet")==0){
                    if(kmc_i.iph_t->protocol==6){
                        kmc_i.tcph_t=tcp_hdr(skb);
                        // include both server and client
                        if(kmc_i.tcph_t->dest==23 || kmc_i.tcph_t->source==23)
                            return 1|kmc_i.negation_flag;
                    }
                }

                else if(strcmp(kmc_i.protocol_name,"smtp")==0){
                    if(kmc_i.iph_t->protocol==6){
                        kmc_i.tcph_t=tcp_hdr(skb);
                        // include both server and client
                        if(kmc_i.tcph_t->dest==25 || kmc_i.tcph_t->source==25)
                            return 1|kmc_i.negation_flag;
                    }
                }

                else if(strcmp(kmc_i.protocol_name,"pop3")==0){
                    if(kmc_i.iph_t->protocol==6){
                        kmc_i.tcph_t=tcp_hdr(skb);
                        // include both server and client
                        if(kmc_i.tcph_t->dest==110 || kmc_i.tcph_t->source==110)
                            return 1|kmc_i.negation_flag;
                    }
                }

                else if(strcmp(kmc_i.protocol_name,"imap")==0){
                    if(kmc_i.iph_t->protocol==6){
                        kmc_i.tcph_t=tcp_hdr(skb);
                        // include both server and client
                        if(kmc_i.tcph_t->dest==143 || kmc_i.tcph_t->source==143)
                            return 1|kmc_i.negation_flag;
                    }
                }

                else if(strcmp(kmc_i.protocol_name,"http")==0){
                    if(kmc_i.iph_t->protocol==6){
                        kmc_i.tcph_t=tcp_hdr(skb);
                        // include both server and client
                        if(kmc_i.tcph_t->dest==80 || kmc_i.tcph_t->source==80)
                            return 1|kmc_i.negation_flag;
                    }
                }

                else if(strcmp(kmc_i.protocol_name,"https")==0){
                    if(kmc_i.iph_t->protocol==6){
                        kmc_i.tcph_t=tcp_hdr(skb);
                        // include both server and client
                        if(kmc_i.tcph_t->dest==443 || kmc_i.tcph_t->source==443)
                            return 1|kmc_i.negation_flag;
                    }
                }

            }
            else
                kmc_i.AUX_str_ptr++;
        }
        return 0|kmc_i.negation_flag;
    }

    else if(strcmp(rule_type,"dip")==0) {

        set_ip_address_wildcard_mask(rule_value);

        kmc_i.kmc_i.ip_byte=inet_addr(kmc_i.ip_addr);


        //negate the wildcard mask
        kmc_i.wm_byte=~inet_addr(kmc_i.wildcard_mask);

        // check if the ip address match
        if((kmc_i.ip_byte & kmc_i.wm_byte)==((unsigned int)kmc_i.iph_t->daddr & kmc_i.wm_byte))
            return 1|kmc_i.negation_flag;

        return 0|kmc_i.negation_flag;

    }


    else if(strcmp(rule_type,"sip")==0) {

        set_ip_address_wildcard_mask(rule_value);

        kmc_i.ip_byte=inet_addr(kmc_i.ip_addr);

        //negate the wildcard mask
        kmc_i.wm_byte=~inet_addr(kmc_i.wildcard_mask);


        // check if the ip address match
        if((kmc_i.ip_byte & kmc_i.wm_byte)==((unsigned int)kmc_i.iph_t->saddr & kmc_i.wm_byte))
            return 1|kmc_i.negation_flag;

        return 0|kmc_i.negation_flag;

    }

}


onebyte_p_t data_match(onebyte_p_t* data_name,struct sk_buff* skb){
    /*
     * This function takes data and checks whether it matches the data specified by data_name
     * or not
     *
     * */
    kmc_i.AUX_functions_returns=get_index_of_data_in_datas(&kmc_i,data_name);
    kmc_i.AUX_data_st_ptr=&kmc_i.datas[kmc_i.AUX_functions_returns];

    // if the data doesnt have any rule it matches every traffic
    if(kmc_i.AUX_data_st_ptr->current_rules==0)
        return 1;
    else{
        int i;
        // we check each rule in the data
        for(i=0;i<kmc_i.AUX_data_st_ptr->current_rules;i++){
            if(rule_match(kmc_i.AUX_data_st_ptr->rules[i].type,kmc_i.AUX_data_st_ptr->rules[i].value,skb)){

                // If the rule matched and type of data was match any
                // return 1
                if(kmc_i.AUX_data_st_ptr->type==0)
                    return 1;
            }
            else {
                // If the rule did not matched and type of data was match all
                // return 0
                if (kmc_i.AUX_data_st_ptr->type == 1)
                    return 0;
            }

        }
        // if non of the rules were matched in the case of match any

        if(kmc_i.AUX_data_st_ptr->type==0)
            return 0;

        // if all of the rules were matched in the case of match all
        return 1;

    }
}



static void talk2user(struct sk_buff *skb) {



    struct nlmsghdr *nlh;
    int pid;
    struct sk_buff *skb_out;
    int res;

    nlh = (struct nlmsghdr *) skb->data;
    kmc_i.kfwpmss = NLMSG_DATA(nlh);
    pid = nlh->nlmsg_pid; /*pid of sending process */


    skb_out = nlmsg_new(4, 0);

    if (!skb_out) {

        printk(KERN_ERR "Failed to allocate new skb\n");
        return;

    }
    nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, 4, 0);
    NETLINK_CB(skb_out).dst_group = 0; /* not in mcast group */

    mutex_lock_interruptible(&kmc_i.thread_lock);

    // data definition
    if (kmc_i.kfwpmss->type == 0b00000000) {


        // copying data_name from kfwp request
        memset(kmc_i.AUX_data_name, 0, MAX_LEN_DATA_NAME);
        strcpy(kmc_i.AUX_data_name, kmc_i.kfwpmss->arg1);

        // copying data_type from kfwp request
        memcpy(&kmc_i.AUX_data_type, kmc_i.kfwpmss->arg2, 1);


        kmc_i.AUX_functions_returns = get_index_of_data_in_datas(&kmc_i, kmc_i.AUX_data_name);

        if (kmc_i.AUX_functions_returns == -1) {

            // This case is show data DATA_NAME
            //  send the reply indicating name does not exist
            //
            if (kmc_i.AUX_data_type != 0 && kmc_i.AUX_data_type != 1) {
                send_kfwp_reply(0b00000100, 0, 0, nlh, pid, skb_out);

            } else {

                kmc_i.AUX_data_st_ptr = &(kmc_i.datas[kmc_i.current_kfw_datas]);

                // zero all that structure ( initialize )
                memset(kmc_i.AUX_data_st_ptr, 0, sizeof(data_t));


                // setting type of the new data
                //
                kmc_i.AUX_data_st_ptr->type = kmc_i.AUX_data_type;

                // setting name of the new data
                strcpy(kmc_i.AUX_data_st_ptr->name, kmc_i.AUX_data_name);

                // update total number of datas_cache in kfw datas_cache
                kmc_i.current_kfw_datas++;


                skb_out = nlmsg_new(4, 0);

                if (!skb_out) {

                    printk(KERN_ERR
                    "Failed to allocate new skb\n");
                    return;

                }
                nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, 4, 0);
                NETLINK_CB(skb_out).dst_group = 0; /* not in mcast group */

                send_kfwp_reply(0b00000000, 0, 0, nlh, pid, skb_out);


            }

        } else {

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
                send_kfwp_reply(0b00000001, 0, 0, nlh, pid, skb_out);

            }
            else {
                kmc_i.AUX_data_st_ptr = &(kmc_i.datas[kmc_i.AUX_functions_returns]);

                if (kmc_i.AUX_data_st_ptr->current_rules != 0) {


                    kmc_i.kfwprepmss = (kfwp_reply_t *) kmalloc(4, GFP_KERNEL);

                    kmc_i.kfwprepmss->status = 0b00000000;
                    kmc_i.kfwprepmss->page_size = 200;
                    kmc_i.kfwprepmss->page_cnt = ((int) (sizeof(data_t) / kfwprepmss->page_size)) + 1;



                    memcpy(nlmsg_data(kmc_i.nlh), kmc_i.kfwprepmss, 4);
                    res = nlmsg_unicast(kmc_i.nl_sk, skb_out, pid);


                    if (res < 0)
                        printk(KERN_INFO
                    "Error while sending bak to user\n");

                    memcpy(kmc_i.AUX_page, kmc_i.AUX_data_st_ptr, 200);



                    int i;
                    for (i = 0; i < kmc_i.kfwprepmss->page_cnt; i++) {

                        skb_out = nlmsg_new(kmc_i.kfwprepmss->page_size, 0);
                        if (!skb_out) {

                            printk(KERN_ERR
                            "Failed to allocate new skb\n");
                            return;

                        }
                        nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, kmc_i.kfwprepmss->page_size, 0);
                        NETLINK_CB(skb_out).dst_group = 0; /* not in mcast group */


                        if (i == kmc_i.kfwprepmss->page_cnt - 1) {
                            memcpy(kmc_i.AUX_page, (void *) kmc_i.AUX_data_st_ptr + i * kmc_i.kfwprepmss->page_size,
                                   sizeof(data_t) - i * kmc_i.kfwprepmss->page_size + 1);

                            memcpy(nlmsg_data(nlh), kmc_i.AUX_page, kmc_i.kfwprepmss->page_size);
                        } else {

                            memcpy(nlmsg_data(nlh), (void *) kmc_i.AUX_data_st_ptr + i * kmc_i.kfwprepmss->page_size,
                                   kmc_i.kfwprepmss->page_size);
                        }
                        res = nlmsg_unicast(kmc_i.nl_sk, skb_out, pid);

                        if (res < 0)
                            printk(KERN_INFO
                        "Error while sending bak to user\n");
                    }


                    kfree(kmc_i.kfwprepmss);
                }

                else
                    send_kfwp_reply(0b00000000, 0, 0, nlh, pid, skb_out);

            }

        }

    }


        // rule definition
    else if (kmc_i.kfwpmss->type == 0b00000001) {

        // copying rule_type from kfwp request
        memset(kmc_i.AUX_data_name, 0, MAX_LEN_DATA_NAME);
        memset(kmc_i.AUX_rule_type, 0, MAX_LEN_RULE_TYPE);
        memset(kmc_i.AUX_rule_value, 0, MAX_LEN_RULE_VALUE);

        strcpy(kmc_i.AUX_rule_type, kmc_i.kfwpmss->arg1);
        strcpy(kmc_i.AUX_rule_value, kmc_i.kfwpmss->arg2);
        strcpy(kmc_i.AUX_data_name, kmc_i.kfwpmss->arg3);

        kmc_i.AUX_functions_returns = get_index_of_rule_in_rules(kmc_i.AUX_data_st_ptr, kmc_i.AUX_rule_type);

        if (kmc_i.AUX_functions_returns == -1) {

            kmc_i.AUX_rule_st_ptr = &(kmc_i.AUX_data_st_ptr->rules[kmc_i.AUX_data_st_ptr->current_rules]);
            //zero the data_with_action
            memset(kmc_i.AUX_rule_st_ptr, 0, sizeof(rule_t));

            strcpy(kmc_i.AUX_rule_st_ptr->type, kmc_i.AUX_rule_type);
            strcpy(kmc_i.AUX_rule_st_ptr->value, kmc_i.AUX_rule_value);

            //update total number of rules in data
            kmc_i.AUX_data_st_ptr->current_rules++;

            send_kfwp_reply(0b00000000, 0, 0, nlh, pid, skb_out);


        } else {

            kmc_i.AUX_rule_st_ptr = &(kmc_i.AUX_data_st_ptr->rules[kmc_i.AUX_functions_returns]);
            memset(kmc_i.AUX_rule_st_ptr->value, 0, strlen(kmc_i.AUX_rule_st_ptr->value));
            strcpy((kmc_i.AUX_rule_st_ptr->value), kmc_i.AUX_rule_value);


            send_kfwp_reply(0b00000000, 0, 0, nlh, pid, skb_out);

        }
    }

        // rule deletion
    else if (kmc_i.kfwpmss->type == 0b10000001) {

        // copying rule_type from kfwp request
        memset(kmc_i.AUX_rule_type, 0, MAX_LEN_RULE_TYPE);

        strcpy(kmc_i.AUX_rule_type, kmc_i.kfwpmss->arg1);



/*
         * Deletion policy:
         *  First we find the type and value of the rule based on splitting
         *  rule command.Then we search these values in the rules array of the
         *  (founded/created) data.After finding the index of that rule , we kmc_i.port_number_array_start
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
         *             kmc_i.port_number_array_start copying each rules bytes to the previous index
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
                    // kmc_i.port_number_array_start copying each rule to the previous index ( shifting to the left)
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

        send_kfwp_reply(0b00000000, 0, 0, nlh, pid, skb_out);


    }

        // clear rules of the data
    else if (kmc_i.kfwpmss->type == 0b01111110) {
        kmc_i.AUX_data_st_ptr->current_rules = 0;
        send_kfwp_reply(0b00000000, 0, 0, nlh, pid, skb_out);

    }



        // clear data_with of the policy
    else if (kmc_i.kfwpmss->type == 0b01111111) {

        kmc_i.AUX_policy_st_ptr->current_data_actions = 0;

        send_kfwp_reply(0b00000000, 0, 0, nlh, pid, skb_out);

    }


        // policy definition
    else if (kmc_i.kfwpmss->type == 0b00000010) {

        memset(kmc_i.AUX_policy_name, 0, MAX_LEN_POLICY_NAME);


        strcpy(kmc_i.AUX_policy_name, kmc_i.kfwpmss->arg1);


        kmc_i.AUX_functions_returns = get_index_of_policy_in_policies(&kmc_i, kmc_i.AUX_policy_name);


        if (kmc_i.AUX_functions_returns == -1) {

            // check if the command issued was show command
            // if sth was written on arg2 means show command was issued
            if (*kmc_i.kfwpmss->arg2 != 0) {

                send_kfwp_reply(0b00000100, 0, 0, nlh, pid, skb_out);



            } else {

                kmc_i.AUX_policy_st_ptr = &(kmc_i.policies[kmc_i.current_kfw_policies]);

                // zero all that structure ( initialize )
                memset(kmc_i.AUX_policy_st_ptr, 0, sizeof(policy_t));


                // setting name of the new policy
                //

                // setting name of the new data
                strcpy(kmc_i.AUX_policy_st_ptr->name, kmc_i.AUX_policy_name);

                // update total number of datas_cache in kfw datas_cache
                kmc_i.current_kfw_policies++;


                skb_out = nlmsg_new(4, 0);

                if (!skb_out) {

                    printk(KERN_ERR
                    "Failed to allocate new skb\n");
                    return;

                }
                nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, 4, 0);
                NETLINK_CB(skb_out).dst_group = 0; /* not in mcast group */

                send_kfwp_reply(0b00000000, 0, 0, nlh, pid, skb_out);

            }

        } else {


            kmc_i.AUX_policy_st_ptr = &(kmc_i.policies[kmc_i.AUX_functions_returns]);


            if (kmc_i.AUX_policy_st_ptr->current_data_actions != 0) {
                kmc_i.kfwprepmss = (kfwp_reply_t *) kmalloc(4, GFP_KERNEL);

                kmc_i.kfwprepmss->status = 0b00000000;
                kmc_i.kfwprepmss->page_size = KFW_PAGE_SIZE;
                kmc_i.kfwprepmss->page_cnt = ((int) (sizeof(policy_t) / kmc_i.kfwprepmss->page_size)) + 1;




                memcpy(nlmsg_data(nlh), kmc_i.kfwprepmss, 4);
                res = nlmsg_unicast(kmc_i.nl_sk, skb_out, pid);

                if (res < 0)
                    printk(KERN_INFO
                "Error while sending bak to user\n");

                memcpy(kmc_i.AUX_page, kmc_i.AUX_data_st_ptr, 200);


                // reallocate for simple reply
                int i = 0;
                for (i = 0; i < kmc_i.kfwprepmss->page_cnt; i++) {

                    skb_out = nlmsg_new(kmc_i.kfwprepmss->page_size, 0);
                    if (!skb_out) {

                        printk(KERN_ERR
                        "Failed to allocate new skb\n");
                        return;

                    }
                    nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, kmc_i.kfwprepmss->page_size, 0);
                    NETLINK_CB(skb_out).dst_group = 0; /* not in mcast group */


                    if (i == kmc_i.kfwprepmss->page_cnt - 1) {
                        memcpy(kmc_i.AUX_page, (void *) kmc_i.AUX_policy_st_ptr + i * kmc_i.kfwprepmss->page_size,
                               sizeof(policy_t) - i * kmc_i.kfwprepmss->page_size + 1);

                        memcpy(nlmsg_data(nlh), kmc_i.AUX_page, kmc_i.kfwprepmss->page_size);
                    } else {

                        memcpy(nlmsg_data(nlh), (void *) kmc_i.AUX_policy_st_ptr + i * kmc_i.kfwprepmss->page_size,
                               kmc_i.kfwprepmss->page_size);
                    }
                    res = nlmsg_unicast(kmc_i.nl_sk, skb_out, pid);

                    if (res < 0)
                        printk(KERN_INFO
                    "Error while sending bak to user\n");
                }


                kfree(kmc_i.kfwprepmss);
            }

            else
                send_kfwp_reply(0b00000000, 0, 0, nlh, pid, skb_out);

        }

    }


        // policy deletion
    else if (kmc_i.kfwpmss->type == 0b10000010) {
        memset(kmc_i.AUX_policy_name, 0, MAX_LEN_POLICY_NAME);


        strcpy(kmc_i.AUX_policy_name, kmc_i.kfwpmss->arg1);


        // delete the policy
        kmc_i.AUX_functions_returns = get_index_of_policy_in_policies(&kmc_i, kmc_i.AUX_policy_name);

        // deletion policy is same as before
        if (kmc_i.AUX_functions_returns != -1) {


            kmc_i.AUX_functions_returns = check_ingress_dependency_on_policy(&ingress_policies, kmc_i.AUX_policy_name);

            if (kmc_i.AUX_functions_returns != -1) {
                //send reply back to userspace telling an ingress policy exists
                // that relie on the policy , cannot delete policy
                send_kfwp_reply(0b00000001, 0, 0, nlh, pid, skb_out);

            } else {
                kmc_i.AUX_functions_returns = check_egress_dependency_on_policy(&egress_policies,
                                                                                kmc_i.AUX_policy_name);

                if (kmc_i.AUX_functions_returns != -1) {
                    //send reply back to userspace telling an egress policy exists
                    // that relie on the policy , cannot delete policy
                    send_kfwp_reply(0b00000010, 0, 0, nlh, pid, skb_out);


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
                    send_kfwp_reply(0b00000000, 0, 0, nlh, pid, skb_out);

                }
            }

        } else {
            //send reply back to userspace telling an the policy
            // does not exist
            send_kfwp_reply(0b00000011, 0, 0, nlh, pid, skb_out);
        }


    }


//
        // data with action definition
    else if (kmc_i.kfwpmss->type == 0b00000011) {

        // copying rule_type from kfwp request
        memset(kmc_i.AUX_data_name, 0, MAX_LEN_DATA_NAME);
        memset(kmc_i.AUX_action_name, 0, MAX_LEN_ACTION_NAME);

        strcpy(kmc_i.AUX_data_name, kmc_i.kfwpmss->arg1);
        strcpy(kmc_i.AUX_action_name, kmc_i.kfwpmss->arg2);



        kmc_i.AUX_functions_returns = get_index_of_data_in_datas(&kmc_i, kmc_i.AUX_data_name);

        if (kmc_i.AUX_functions_returns == -1)
            send_kfwp_reply(0b00000001, 0, 0, nlh, pid, skb_out);

        else {
            kmc_i.AUX_functions_returns = get_index_of_datawithaction_in_policies(kmc_i.AUX_policy_st_ptr,
                                                                                  kmc_i.AUX_data_name);

            if (kmc_i.AUX_functions_returns == -1) {

                kmc_i.AUX_data_action_st_ptr = &(kmc_i.AUX_policy_st_ptr->data_with_actions[kmc_i.AUX_policy_st_ptr->current_data_actions]);

                //zero the data_with_action
                memset(kmc_i.AUX_data_action_st_ptr, 0, sizeof(data_with_action_t));

                strcpy(kmc_i.AUX_data_action_st_ptr->data_name, kmc_i.AUX_data_name);
                strcpy(kmc_i.AUX_data_action_st_ptr->action, kmc_i.AUX_action_name);

                // update total number of data_with_action entities in the policy
                kmc_i.AUX_policy_st_ptr->current_data_actions++;

                send_kfwp_reply(0b00000000, 0, 0, nlh, pid, skb_out);



            } else {
                kmc_i.AUX_data_action_st_ptr = &(kmc_i.AUX_policy_st_ptr->data_with_actions[kmc_i.AUX_functions_returns]);

                memset(&(kmc_i.AUX_data_action_st_ptr->action), 0, MAX_LEN_ACTION_NAME);

                strcpy(kmc_i.AUX_data_action_st_ptr->action, kmc_i.AUX_action_name);

                send_kfwp_reply(0b00000001, 0, 0, nlh, pid, skb_out);


            }
        }
    }

        // data with action deletion
    else if (kmc_i.kfwpmss->type == 0b10000011) {



        // copying rule_type from kfwp request
        memset(kmc_i.AUX_data_name, 0, MAX_LEN_DATA_NAME);
        memset(kmc_i.AUX_action_name, 0, MAX_LEN_ACTION_NAME);

        strcpy(kmc_i.AUX_data_name, kmc_i.kfwpmss->arg1);
        strcpy(kmc_i.AUX_action_name, kmc_i.kfwpmss->arg2);


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
                    // kmc_i.port_number_array_start copying each rule to the previous index ( shifting to the left)
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

        send_kfwp_reply(0b00000000, 0, 0, nlh, pid, skb_out);

    }


        // data deletion
    else if (kmc_i.kfwpmss->type == 0b10000000) {

        // copying data_name from kfwp request
        memset(kmc_i.AUX_data_name, 0, MAX_LEN_DATA_NAME);
        strcpy(kmc_i.AUX_data_name, kmc_i.kfwpmss->arg1);

        kmc_i.AUX_functions_returns = get_index_of_data_in_datas(&kmc_i, kmc_i.AUX_data_name);

        if (kmc_i.AUX_functions_returns != -1) {

            // check policy dependecy
            kmc_i.AUX_functions_returns = check_policy_dependeny_on_data(&kmc_i, kmc_i.AUX_data_name);

            // data cannot be deleted because there are some policies_cache that
            // depends on this data
            if (kmc_i.AUX_functions_returns != -1) {
                // send reply to userspace indicating that this data cannot be deleted becuase of
                // dependency

                send_kfwp_reply(0b00000011, 0, 0, nlh, pid, skb_out);


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
                send_kfwp_reply(0b00000000, 0, 0, nlh, pid, skb_out);

            }

        } else {
            // send reply to userspace indicating that this data does not exist
            send_kfwp_reply(0b00000010, 0, 0, nlh, pid, skb_out);
        }

    }


        //show datas_cache
    else if (kmc_i.kfwpmss->type == 0b00001110) {

        kmc_i.kfwprepmss = (kfwp_reply_t *) kmalloc(4, GFP_KERNEL);

        kmc_i.kfwprepmss->status = 0b00000000;
        kmc_i.kfwprepmss->page_size = KFW_DATA_HEADER_SIZE;
        kmc_i.kfwprepmss->page_cnt = kmc_i.current_kfw_datas;



        memcpy(nlmsg_data(nlh), kmc_i.kfwprepmss, 4);
        res = nlmsg_unicast(kmc_i.nl_sk, skb_out, pid);

        if (res < 0)
            printk(KERN_INFO
        "Error while sending bak to user\n");



        int i = 0;
        for (i = 0; i < kmc_i.kfwprepmss->page_cnt; i++) {

            skb_out = nlmsg_new(kmc_i.kfwprepmss->page_size, 0);
            if (!skb_out) {

                printk(KERN_ERR
                "Failed to allocate new skb\n");
                return;

            }
            nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, kmc_i.kfwprepmss->page_size, 0);
            NETLINK_CB(skb_out).dst_group = 0; /* not in mcast group */



            memcpy(nlmsg_data(nlh), (void *) &kmc_i.datas + i * sizeof(data_t), kmc_i.kfwprepmss->page_size);

            res = nlmsg_unicast(kmc_i.nl_sk, skb_out, pid);


            if (res < 0)
                printk(KERN_INFO
            "Error while sending bak to user\n");
        }


        kfree(kmc_i.kfwprepmss);


    }


        // show policies_cache
    else if (kmc_i.kfwpmss->type == 0b00001111) {
        kmc_i.kfwprepmss = (kfwp_reply_t *) kmalloc(4, GFP_KERNEL);

        kmc_i.kfwprepmss->status = 0b00000000;
        kmc_i.kfwprepmss->page_size = KFW_POLICY_HEADER_SIZE;
        kmc_i.kfwprepmss->page_cnt = kmc_i.current_kfw_policies;

        memcpy(nlmsg_data(nlh), kmc_i.kfwprepmss, 4);
        res = nlmsg_unicast(kmc_i.nl_sk, skb_out, pid);

        if (res < 0)
            printk(KERN_INFO
        "Error while sending bak to user\n");



        int i = 0;
        for (i = 0; i < kmc_i.kfwprepmss->page_cnt; i++) {

            skb_out = nlmsg_new(kmc_i.kfwprepmss->page_size, 0);
            if (!skb_out) {

                printk(KERN_ERR
                "Failed to allocate new skb\n");
                return;

            }
            nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, kmc_i.kfwprepmss->page_size, 0);
            NETLINK_CB(skb_out).dst_group = 0; /* not in mcast group */

            memcpy(nlmsg_data(nlh), (void *) &kmc_i.policies + i * sizeof(policy_t), kmc_i.kfwprepmss->page_size);


            res = nlmsg_unicast(kmc_i.nl_sk, skb_out, pid);

            if (res < 0)
                printk(KERN_INFO
            "Error while sending bak to user\n");
        }


        kfree(kmc_i.kfwprepmss);


    }


        // service policy command
    else if (kmc_i.kfwpmss->type == 0b00000100) {

        // setting needed vaiables
        memset(kmc_i.AUX_policy_name, 0, MAX_LEN_POLICY_NAME);
        memset(kmc_i.AUX_interface_name, 0, MAX_LEN_INTERFACE_NAME);
        memset(kmc_i.AUX_policy_direction, 0, MAX_LEN_POLICY_DIRECTION);

        // copying policy_name from kfwp request

        strcpy(kmc_i.AUX_policy_name, kmc_i.kfwpmss->arg1);
        strcpy(kmc_i.AUX_interface_name, kmc_i.kfwpmss->arg2);
        strcpy(kmc_i.AUX_policy_direction, kmc_i.kfwpmss->arg3);

        kmc_i.AUX_functions_returns = get_index_of_policy_in_policies(&kmc_i, kmc_i.AUX_policy_name);

        if (kmc_i.AUX_functions_returns == -1)

            send_kfwp_reply(0b00000001, 0, 0, nlh, pid, skb_out);

        else {

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

                    kmc_i.kfwprepmss = (kfwp_reply_t *) kmalloc(4, GFP_KERNEL);


                    //send reply back to userspace
                    // saying error of not existance of the data
                    send_kfwp_reply(0b00000000, 0, 0, nlh, pid, skb_out);


                } else {

                    // we already have defined a policy on the interface
                    // we want to update it we new/old policy.i said old
                    // becuase i dont want to check whether the old and the new one
                    // are same or not

                    // we clear the previous plocy name
                    memset(&ingress_policies.policyWithInterfaces[kmc_i.AUX_functions_returns], 0, MAX_LEN_POLICY_NAME);
                    strcpy(ingress_policies.policyWithInterfaces[kmc_i.AUX_functions_returns].policy_name,
                           kmc_i.AUX_policy_name);

                    send_kfwp_reply(0b10000000, 0, 0, nlh, pid, skb_out);

                }
            }
            else {
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

                    send_kfwp_reply(0b00000000, 0, 0, nlh, pid, skb_out);


                } else {

                    // we already have defined a policy on the interface
                    // we want to update it we new/old policy.i said old
                    // becuase i dont want to check whether the old and the new one
                    // are same or not

                    // we clear the previous plocy name
                    memset(&egress_policies.policyWithInterfaces[kmc_i.AUX_functions_returns], 0, MAX_LEN_POLICY_NAME);
                    strcpy(egress_policies.policyWithInterfaces[kmc_i.AUX_functions_returns].policy_name,
                           kmc_i.AUX_policy_name);


                    send_kfwp_reply(0b10000000, 0, 0, nlh, pid, skb_out);

                }
            }
        }
    }



        // no service policy command
    else if (kmc_i.kfwpmss->type == 0b10000100) {

        // setting needed vaiables
        memset(kmc_i.AUX_policy_name, 0, MAX_LEN_POLICY_NAME);
        memset(kmc_i.AUX_interface_name, 0, MAX_LEN_INTERFACE_NAME);
        memset(kmc_i.AUX_policy_direction, 0, MAX_LEN_POLICY_DIRECTION);

        // copying policy_name from kfwp request

        strcpy(kmc_i.AUX_policy_name, kmc_i.kfwpmss->arg1);
        strcpy(kmc_i.AUX_interface_name, kmc_i.kfwpmss->arg2);
        strcpy(kmc_i.AUX_policy_direction, kmc_i.kfwpmss->arg3);

        kmc_i.AUX_functions_returns = get_index_of_policy_in_policies(&kmc_i, kmc_i.AUX_policy_name);

        if (kmc_i.AUX_functions_returns == -1)

            send_kfwp_reply(0b00000001, 0, 0, nlh, pid, skb_out);
        else {

            if (strcmp(kmc_i.AUX_policy_direction, "out") == 0) {
                kmc_i.AUX_functions_returns = get_index_of_policyint_in_egress(&egress_policies,
                                                                               kmc_i.AUX_interface_name);

                if (kmc_i.AUX_functions_returns != -1) {

                    // check whether tha policy_name user entered , matched the policy name in policywithint
                    // structure.i dont want user to be able to delete a service with policy that exist
                    // in kfw but not have been set on the interface

                    if (strncmp(egress_policies.policyWithInterfaces[kmc_i.AUX_functions_returns].policy_name,
                                kmc_i.AUX_policy_name, strlen(kmc_i.AUX_policy_name)) != 0) {

                        // send reply to user and tell him/her that this policy exsit on kfw but has not set
                        // on the interface anymore
                        send_kfwp_reply(0b00000010, 0, 0, nlh, pid, skb_out);


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
                        send_kfwp_reply(0b00000000, 0, 0, nlh, pid, skb_out);

                    }

                } else
                    send_kfwp_reply(0b00000011, 0, 0, nlh, pid, skb_out);


            }
            else {

                kmc_i.AUX_functions_returns = get_index_of_policyint_in_ingress(&ingress_policies,
                                                                                kmc_i.AUX_interface_name);

                if (kmc_i.AUX_functions_returns != -1) {

                    // check whether tha policy_name user entered , matched the policy name in policywithint
                    // structure.i dont want user to be able to delete a service with policy that exist
                    // in kfw but not have been set on the interface

                    if (strncmp(ingress_policies.policyWithInterfaces[kmc_i.AUX_functions_returns].policy_name,
                                kmc_i.AUX_policy_name, strlen(kmc_i.AUX_policy_name)) != 0) {

                        // send reply to user and tell him/her that this policy exsit on kfw but has not set
                        // on the interface anymore
                        send_kfwp_reply(0b00000010, 0, 0, nlh, pid, skb_out);

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
                            send_kfwp_reply(0b00000000, 0, 0, nlh, pid, skb_out);

                        }

                    }
                } else {
                    // send reply back to user telling no policy has been set on
                    // the interface specified
                    send_kfwp_reply(0b00000011, 0, 0, nlh, pid, skb_out);

                }
            }
        }
    }




        // update ingress policies_cache cache
    else if (kmc_i.kfwpmss->type == 0b00001000) {

        kmc_i.kfwprepmss = (kfwp_reply_t *) kmalloc(4, GFP_KERNEL);

        kmc_i.kfwprepmss->status = 0b00000000;
        kmc_i.kfwprepmss->page_size = sizeof(policy_with_int_t);
        kmc_i.kfwprepmss->page_cnt = ingress_policies.current_ingress_policies;

        memcpy(nlmsg_data(nlh), kmc_i.kfwprepmss, 4);
        res = nlmsg_unicast(kmc_i.nl_sk, skb_out, pid);

        if (res < 0)
            printk(KERN_INFO
        "Error while sending bak to user\n");


        int i = 0;
        for (i = 0; i < kmc_i.kfwprepmss->page_cnt; i++) {

            skb_out = nlmsg_new(kmc_i.kfwprepmss->page_size, 0);
            if (!skb_out) {

                printk(KERN_ERR
                "Failed to allocate new skb\n");
                return;

            }
            nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, kmc_i.kfwprepmss->page_size, 0);
            NETLINK_CB(skb_out).dst_group = 0; /* not in mcast group */

            memcpy(nlmsg_data(nlh), (void *) &ingress_policies.policyWithInterfaces + i * sizeof(policy_with_int_t),
                   kmc_i.kfwprepmss->page_size);


            res = nlmsg_unicast(kmc_i.nl_sk, skb_out, pid);


            if (res < 0)
                printk(KERN_INFO
            "Error while sending bak to user\n");
        }


        kfree(kmc_i.kfwprepmss);


    }



        // update egress policies_cache cache
    else if (kmc_i.kfwpmss->type == 0b00001001){

        kmc_i.kfwprepmss = (kfwp_reply_t *) kmalloc(4, GFP_KERNEL);

        kmc_i.kfwprepmss->status = 0b00000000;
        kmc_i.kfwprepmss->page_size=sizeof(policy_with_int_t);
        kmc_i.kfwprepmss->page_cnt =egress_policies.current_egress_policies;

        memcpy(nlmsg_data(nlh), kmc_i.kfwprepmss, 4);
        res = nlmsg_unicast(kmc_i.nl_sk, skb_out, pid);

        if (res < 0)
            printk(KERN_INFO"Error while sending bak to user\n");


        int i;
        for(i=0;i<kmc_i.kfwprepmss->page_cnt;i++){

            skb_out = nlmsg_new(kmc_i.kfwprepmss->page_size,0);
            if(!skb_out)
            {
                printk(KERN_ERR "Failed to allocate new skb\n");
                return;
            }

            nlh=nlmsg_put(skb_out,0,0,NLMSG_DONE,kmc_i.kfwprepmss->page_size,0);
            NETLINK_CB(skb_out).dst_group = 0; /* not in mcast group */

            memcpy(nlmsg_data(nlh), (void *)&egress_policies.policyWithInterfaces + i * sizeof(policy_with_int_t),kmc_i.kfwprepmss->page_size);

            res = nlmsg_unicast(kmc_i.nl_sk, skb_out, pid);

            if (res < 0)
                printk(KERN_INFO"Error while sending bak to user\n");
        }


        kfree(kmc_i.kfwprepmss);
        A



    }

    mutex_unlock(&kmc_i.thread_lock);


}



static unsigned int egress_hfunc(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {

    struct iphdr *iph;
    struct udphdr *udph;

    if (!skb)
        return NF_ACCEPT;

    mutex_lock_interruptible(&kmc_i.thread_lock);

    kmc_i.iph_t = ip_hdr(skb);

    // find policy_with_int by interface name
    kmc_i.AUX_functions_returns = get_index_of_policyint_in_egress(&egress_policies, state->out->name);


    if(kmc_i.AUX_functions_returns!=-1) {
        // find policy with policy name
        kmc_i.AUX_functions_returns = get_index_of_policy_in_policies(&kmc_i,
                                                                      egress_policies.policyWithInterfaces[kmc_i.AUX_functions_returns].policy_name);
        kmc_i.AUX_policy_st_ptr=&(kmc_i.policies[kmc_i.AUX_functions_returns]);
        // if the policy doesnt have any data_with_action entry
        // default policy is dropping the packet
        if (kmc_i.AUX_policy_st_ptr->current_data_actions == 0) {
            mutex_unlock(&kmc_i.thread_lock);
            return NF_DROP;
        } else {
            int i;
            for (i = 0; i < kmc_i.AUX_policy_st_ptr->current_data_actions; i++) {
                kmc_i.AUX_functions_returns = data_match(kmc_i.AUX_policy_st_ptr->data_with_actions[i].data_name, skb);
                // The data matched with the traffic
                if (kmc_i.AUX_functions_returns) {
                    // check the action corresponding to the data
                    if (strcmp(kmc_i.AUX_policy_st_ptr->data_with_actions[i].action, "permit") ==0) {
                        mutex_unlock(&kmc_i.thread_lock);
                        return NF_ACCEPT;
                    }
                    // else drop the traffic
                    mutex_unlock(&kmc_i.thread_lock);
                    return NF_DROP;
                }
            }
            // if no data matched , default policy is to drop
            mutex_unlock(&kmc_i.thread_lock);
            return NF_DROP;

        }
    }
    // if there was no policy found for the interface
    // forward the traffic
    mutex_unlock(&kmc_i.thread_lock);
    return NF_ACCEPT;

}


static unsigned int ingress_hfunc(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {

    struct iphdr *iph;
    struct udphdr *udph;

    if (!skb)
        return NF_ACCEPT;

    mutex_lock_interruptible(&kmc_i.thread_lock);

    kmc_i.iph_t = ip_hdr(skb);

    // find policy_with_int by interface name
    kmc_i.AUX_functions_returns = get_index_of_policyint_in_ingress(&ingress_policies, state->in->name);


    if(kmc_i.AUX_functions_returns!=-1) {
        // find policy with policy name
        kmc_i.AUX_functions_returns = get_index_of_policy_in_policies(&kmc_i,
                                                                      ingress_policies.policyWithInterfaces[kmc_i.AUX_functions_returns].policy_name);
        kmc_i.AUX_policy_st_ptr=&(kmc_i.policies[kmc_i.AUX_functions_returns]);
        // if the policy doesnt have any data_with_action entry
        // default policy is dropping the packet
        if (kmc_i.AUX_policy_st_ptr->current_data_actions == 0) {
            mutex_unlock(&kmc_i.thread_lock);
            return NF_DROP;
        } else {
            int i;
            for (i = 0; i < kmc_i.AUX_policy_st_ptr->current_data_actions; i++) {
                kmc_i.AUX_functions_returns = data_match(kmc_i.AUX_policy_st_ptr->data_with_actions[i].data_name, skb);
                // The data matched with the traffic
                if (kmc_i.AUX_functions_returns) {
                    // check the action corresponding to the data
                    if (strcmp(kmc_i.AUX_policy_st_ptr->data_with_actions[i].action, "permit") ==0) {
                        mutex_unlock(&kmc_i.thread_lock);
                        return NF_ACCEPT;
                    }
                    // else drop the traffic
                    mutex_unlock(&kmc_i.thread_lock);
                    return NF_DROP;
                }
            }
            // if no data matched , default policy is to drop
            mutex_unlock(&kmc_i.thread_lock);
            return NF_DROP;

        }
    }
    // if there was no policy found for the interface
    // forward the traffic
    mutex_unlock(&kmc_i.thread_lock);
    return NF_ACCEPT;

}

