/*
 *
 *  THIS FILE CONTAINS KERNEL MODULE MAIN FUNCTIONS PROTOTYPES
 *
 *
 *
 *  Written By :  Kiarash Sedghi
 *
 *
 * */
#ifndef KFW_KFW_KERNEL_FUNCTIONS_H
#define KFW_KFW_KERNEL_FUNCTIONS_H


onebyte_np_t get_index_of_data_in_datas(kmc_controles_t *kmci,onebyte_p_t *data_name);
onebyte_np_t get_index_of_rule_in_rules(data_t *data_st ,onebyte_p_t *rule_type );
onebyte_np_t get_index_of_policy_in_policies(kmc_controles_t *kmci,onebyte_p_t *policy_name);
onebyte_np_t get_index_of_datawithaction_in_policies(policy_t *policy , onebyte_p_t *data_name);
onebyte_np_t check_policy_dependeny_on_data(kmc_controles_t *kmci,onebyte_p_t *data_name);
onebyte_np_t check_ingress_dependency_on_policy(ingress_policies_t *ingress_policies,onebyte_p_t *policy_name);
onebyte_np_t check_egress_dependency_on_policy(egress_policies_t *egress_policies,onebyte_p_t *policy_name);

onebyte_np_t get_index_of_policyint_in_egress(egress_policies_t *egressPolicies ,onebyte_p_t*interface_name);
onebyte_np_t get_index_of_policyint_in_ingress(ingress_policies_t *ingressPolicies ,onebyte_p_t *interface_name);












#endif //KFW_KFW_KERNEL_FUNCTIONS_H
