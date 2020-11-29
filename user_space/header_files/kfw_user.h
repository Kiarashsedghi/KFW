/*
 *
 *  THIS FILE CONTAINS KFW MAIN PROGRAM CONTROLLERS
 *
 *
 *
 *  Written By :  Kiarash Sedghi
 *
 *
 * */


#ifndef KFW_KFW_
#define KFW_KFW_H
#endif //KFW_KFW_H

#include <sys/socket.h>
#include <linux/netlink.h>
#include "kfw_dstructures.h"





typedef struct regex regex__t;
typedef struct kfw_controls kfw_controls_t;
typedef struct kfwp_controls kfwp_controls_t;


struct regex{

    /*

     * This Structure defines variables which are used for handling regexes
       defined for command line commands

     */
    
    regex_t regex_back_to_previous_mode;
    regex_t regex_quit_exit;
    regex_t regex_nothing_entered;
    regex_t regex_rule_definition;
    regex_t regex_rule_deletion;
    regex_t regex_data_definition;
    regex_t regex_data_deletion;
    regex_t regex_policy_deletion;
    regex_t regex_policy_definition;
    regex_t regex_data_action_definition;
    regex_t regex_data_action_deletion;


    /*

      quick show can be issued when you are in either :
        data definition mode
        policy definition

    */
    regex_t regex_quick_show;
    regex_t regex_quick_clear;

    regex_t regex_service_policy_definition;
    regex_t regex_service_policy_deletion;


    regex_t regex_show_datas;
    regex_t regex_show_polices;
    regex_t regex_show_data_command;
    regex_t regex_show_policy_command;
    regex_t regex_show_polices_with_dir;
    regex_t regex_show_policies_with_int;
    regex_t regex_show_policies_with_int_dir;


};


struct kfw_controls{

    /*
     * This structure contains auxiliary variables which are helpful to prevent
     * redefining the same variables several times during the code.
     *
     * This is because of efficiency.
     *
     * For example , whenever user wants to create new data , we had to allocate a new data_t,
     * fill the fields of that structure and then copy it to datas_cache array.This method gradually
     * increases memory usage , the solution can be maintaining some variables and pointers ,
     * and whenever we want to create for example a new data or a new rule , just by some definite
     * variables , handle all the operation.
     *
     *
     * */



    onebyte_p_t user_command[MAX_LEN_USER_COMMAND];



    /*
     * AUX_data_st_ptr is useful when you create multiple data structures of type data_t.
     *
     * It stores the address of the next available cache space in datas_cache array so
     * it is not necessary that for each data_t , you declare a new variable to save its contents and
     * then copy those contents in data cache
     */
    data_t *AUX_data_st_ptr;
    onebyte_p_t AUX_data_name[MAX_LEN_DATA_NAME];
    onebyte_p_t AUX_data_type;


    /*
     * AUX_policy_st_ptr is useful when you create multiple data structures of type policy_t.
     *
     * It stores the address of the next available cache space in policies_cache array so
     * it is not necessary that for each policy_t , you declare a new variable to save its contents and
     * then copy those contents in policies_cache cache
     */

    policy_t *AUX_policy_st_ptr;
    onebyte_p_t AUX_policy_name[MAX_LEN_POLICY_NAME];



    /*
     * AUX_data_action_st_ptr is useful when you create multiple data structures of type data_with_action_t.
     *
     * It stores the address of the next available cache space in policies_cache array so
     * it is not necessary that for each policy_t , you declare a new variable to save its contents and
     * then copy those contents in policy cache
     */

    data_with_action_t *AUX_data_action_st_ptr;
    onebyte_p_t AUX_action_name[MAX_LEN_ACTION_NAME];



    /*
     * 2 below , are useful when issuing (no)? service command
     * */
    onebyte_p_t AUX_interface_name[MAX_LEN_INTERFACE_NAME];
    onebyte_p_t AUX_policy_direction[MAX_LEN_POLICY_DIRECTION];



    /*
     * AUX_rule_st_ptr is useful when you create multiple data structures of type rule_t.
     *
     *
     */
    rule_t *AUX_rule_st_ptr;
    onebyte_p_t AUX_rule_type[MAX_LEN_RULE_TYPE];
    onebyte_p_t AUX_rule_value[MAX_LEN_RULE_VALUE];






    /*
     * policies_cache : a cache space which store policy_t structures;
     * datas_cache : a cache space which store data_t structures
     *
     *
     * current_kfw_datas : total number of data_t structures currently existing
     *                     in datas_cache cache.
     *
     * current_kfw_policies : total number of policy_t structures currently existing
     *                        in policies_cache cache.
     * */
    onebyte_p_t current_kfw_datas;
    onebyte_p_t current_kfw_policies;
    policy_t policies_cache[MAX_POLICY_IN_KFW];
    data_t datas_cache[MAX_DATA_IN_KFW];


    /*
     *  AUX_functions_returns is used for holding return value of any
     *  function call we have in our program
     *
     * */
    twobyte_np_t AUX_functions_returns;


};


struct kfwp_controls{

    /*
     * This structure stores necessary variables which are used for
     * kfwp and communicating with kernel module.
     *
     * These are netlink api variables.
     *
     * */

    kfwp_req_t *kfwp_req_msg;
    kfwp_reply_t *kfwp_rep_msg;

    struct sockaddr_nl src_addr, dest_addr;
    struct nlmsghdr *nlh ;
    struct iovec iov;
    int sock_fd;
    struct msghdr msg;

};

