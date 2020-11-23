/*
 *
 *  THIS FILE CONTAINS KFW MODULE MAIN FUNCTIONS
 *
 *
 *
 *  Written By :  Kiarash Sedghi
 *
 *
 * */


#include "kfw_kernel.h"
#include "kfw_kernel_functions.h"


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