/*
 *
 *  THIS FILE CONTAINS KFW MAIN FUNCTIONS PROTOTYPES
 *
 *
 *
 *  Written By :  Kiarash Sedghi
 *
 *
 * */

#ifndef KFW_KFW_USER_FUNCTIONS_H
#define KFW_KFW_USER_FUNCTIONS_H



twobyte_p_t  talk_2_module(consistency_flags_t *consistencyFlags, kfw_controls_t *kfw_controls, kfwp_controls_t *kfwp_controls , onebyte_p_t type, onebyte_p_t*arg1, onebyte_p_t  *arg2, onebyte_p_t *arg3, data_t *data_ptr , policy_t * policy_ptr, ingress_policies_t *ingress_policies_ptr, egress_policies_t *egress_policies_t);


void compile_kfw_cmds_regexes(regex__t *kfwregex);

void printe(char * error_message);

void strnsplit(onebyte_p_t *str, onebyte_p_t position , onebyte_p_t * dst);

void split_data_def_del_cmd(onebyte_p_t * data_def , onebyte_p_t *data_name , onebyte_p_t *type , onebyte_p_t data_name_pos , onebyte_p_t show_or_no_len);
void split_rule_def_del_cmd(onebyte_p_t *rule_def, onebyte_p_t *rule_name, onebyte_p_t *rule_value , onebyte_p_t name_pos , onebyte_p_t value_pos);
void split_policy_def_del_show_cmd(onebyte_p_t *policy_def, onebyte_p_t *policy_name , onebyte_p_t name_pos , onebyte_p_t show_or_no_len);
void split_data_action_def_del_cmd(onebyte_p_t *data_with_action_cmd, onebyte_p_t *data_name, onebyte_p_t *action , onebyte_p_t data_name_pos , onebyte_p_t action_pos);
void split_service_policy_def_del_cmd(onebyte_p_t *service_policy_cmd, onebyte_p_t *policy_name, onebyte_p_t *interface_name , onebyte_p_t * direction,
                                      onebyte_p_t policy_name_pos , onebyte_p_t interface_name_pos, onebyte_p_t direction_pos);


onebyte_np_t getindex_data_in_data_cache(kfw_controls_t *kfw_controls, onebyte_p_t *data_name);
onebyte_np_t getindex_policy_in_policy_cache(kfw_controls_t *kfw_controls, onebyte_p_t *policy_name);


#endif //KFW_KFW_USER_FUNCTIONS_H
