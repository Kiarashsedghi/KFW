/*
 *  THIS FILE CONTAINS KERNEL MODULE‌ MAIN PARAMETERS
 *
 *
 *  Written By :  Kiarash Sedghi
 *
 *
 * */

#ifndef KFW_KFW_PARAMETERS_H
#define KFW_KFW_PARAMETERS_H



/*
 *
 *  GLOBAL CONTROL PARAMETERS
 *
 *
 * */


// Parameters that indicate the length policies
#define MAX_LEN_RULE_TYPE 10
#define MAX_LEN_RULE_VALUE 50
#define MAX_LEN_DATA_NAME 10
#define MAX_LEN_POLICY_NAME 10
#define MAX_LEN_INTERFACE_NAME 10
#define MAX_LEN_ACTION_NAME 7
#define MAX_LEN_POLICY_DIRECTION 4
#define MAX_LEN_KFWP_ARG1 10
#define MAX_LEN_KFWP_ARG2 32
#define MAX_LEN_KFWP_ARG3 10
#define MAX_LEN_USER_COMMAND 40
// --------------------------------------------



// Parameters that control quantity policy_cache
#define MAX_RULES_IN_DATA  10
#define MAX_DATA_IN_KFW  10
#define MAX_POLICY_IN_KFW 10
#define MAX_DATA_ACTIONS_IN_POLICY 20

#define MAX_INGRESS_POLICIES 100
#define MAX_EGRESS_POLICIES 100
// --------------------------------------------



// Parameters that control netlink
#define NETLINK_USER 31
#define LEN_kfwp_req 53




#endif //KFW_KFW_PARAMETERS_H
