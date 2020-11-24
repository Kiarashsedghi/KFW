/*
 *
 *  THIS FILE CONTAINS THE MAIN DATA STRUCTURES AND TYPES USED IN KERNEL MODULE
 *
 *
 *  Written By :  Kiarash Sedghi
 *
 *
 * */

#ifndef KFW_KFW_DSTRUCTURES_H
#define KFW_KFW_DSTRUCTURES_H
#endif //KFW_KFW_DSTRUCTURES_H


#include "linux/kfw_parameters.h"


// Bytes types
typedef signed char onebyte_np_t;
typedef unsigned char onebyte_p_t;
typedef unsigned short twobyte_p_t;
typedef signed short twobyte_np_t;


// Kernel Module main data structures types
typedef struct rule rule_t;
typedef struct data data_t;
typedef struct data_with_action data_with_action_t;
typedef struct policy policy_t;
typedef struct policy_with_int policy_with_int_t;
typedef struct ingress_policies ingress_policies_t;
typedef struct egress_policies egress_policies_t;
typedef struct kfw_controls kfw_controls_t;




// KFWP messages data structures types
typedef struct kfwp_request kfwp_req_t;
typedef struct kfwp_reply kfwp_reply_t;




struct kfwp_request{

    /*
     * This structure is kfwp request message
     *
     *
              1B           10B                          32B                       10B
           -------- ------------------ ------------------------------------ -----------------
          |  TYPE  |      ARG1        |                 ARG2               |       ARG3      |
           -------- ------------------ ------------------------------------ -----------------



          TYPE : 1 Byte
             > This field defines the type of request,
             > Type of request defines the type of command that has been issued in kfw program files

                  --- --- --- --- --- --- ---
                 | N | X | X | X | X | X | X |
                  --- --- --- --- --- --- ---

             > First bit of TYPE is Negation bit.For commands that accepts
               the no form ( negate the command with (no) ) , we have not allocated a new type
               message but we make the first bit to 1 , indicating that the command is negation of
               what has been entered.

               Ex:
                 TYPE: ‌00000000
                    data DATA_NAME (all/any)
                 TYPE: 10000000
                    no data DATA_NAME (all/any)


          ARG1,ARG2,ARG3 :
               > These fields contains our commands arguments.Maximum number of parameters
                 in kfw command set is 3.

               > ARG2 is longer because in ( rule definition ) command it contains the rule value
                 and rule value for specifying ip address are at maximum 30(IP/Wildcard).

               > ARG1 and ARG3 length depends on the name length policy_cache for policy name , data name
                 rule name & ....

               > ARG3 for ( service commands ) will contain the policy direction.



           ARG1 length :: MAX_LEN_KFWP_ARG1
           ARG2 length :: MAX_LEN_KFWP_ARG2
           ARG3 length :: MAX_LEN_KFWP_ARG3


     *
     * */


    onebyte_p_t type;
    onebyte_p_t arg1[MAX_LEN_KFWP_ARG1];
    onebyte_p_t arg2[MAX_LEN_KFWP_ARG2];
    onebyte_p_t arg3[MAX_LEN_KFWP_ARG3];
};

struct kfwp_reply{


    /*
     *
     * This structure is kfwp reply message
     *
             1B           1B               2B
           ---------- ------------ ------------------------
          |  STATUS  |  PAGE_CNT  |        PAGE_SIZE       |
           ---------- ------------ ------------------------

        STATUS:
            Size: 1 Byte
            > This field represents the result of executing the request that has
              been sent to the kernel.

            ** For more information on status code , read kfwp_status_codes_doc .

        PAGE_CNT‌:
            Size: 1 Byte
            > This field represents the number of pages of data that kernel wants
              to send to the kernel

        PAGE_SIZE:
            Size: ‌2 Bytes
            > This field represents the page size.
            > Page size is defined by kernel module not kfw program files program.


        ******************************************************
        *  Kernel modules sends data in page units.          *
        *  The reason is netlink sockets are datagram based. *
        ******************************************************


     *
     * */


    onebyte_p_t status;
    onebyte_p_t page_cnt;
    twobyte_p_t page_size;
};

struct rule {
    /*
     * This structure is for defining rules to match traffic.
     *
     * For more information on different rule types and their possible values
     * consult the kfw_rule_doc.
     *
     *
     * */

    onebyte_p_t type[MAX_LEN_RULE_TYPE];
    onebyte_p_t value[MAX_LEN_RULE_VALUE];
};

struct data {

    /*
     * This structure is to define user defined traffics;
     *
     * These traffics are matched based on the rules defined in the data structure you defined.
     *
     *
     *  NAME:
     *    Size: MAX_LEN_DATA_NAME Bytes
     *    > Each data has a user defined name unique name
     *    > This name can be anything.
     *
     *   TYPE:
     *    Size: 1 Byte
     *    > match all:  1
     *    > match any:  0 (default type)
     *
     *   CONSISTENCY:
     *    Size: 1 Byte
     *    > This field indicates whether the data in the cache is consistent with
     *      kernel module or not
     *    >
     *      Consistency: 1
     *      Inconsistency: 0
     *
     *   CURRENT_RULES:
     *      Size: 1 Byte
     *      > This fields show the total number of current rules defined for this data
     *
     *   RULES:
     *      Size: sizeof(rule_t)*MAX_RULES_IN_DATA
     *      > This field is an array of all rules defined for this data
     *
     * */


    onebyte_p_t name[MAX_LEN_DATA_NAME];
    onebyte_p_t type;
    onebyte_p_t consistency;
    onebyte_p_t current_rules;
    rule_t rules[MAX_RULES_IN_DATA];
};

struct data_with_action{

    /*
     * This structure is mapping of a data structure with an action and is
     * used when creating policies.Each policy is set of datas that an action has mapped to each of
     * them.
     *
     * DATA_NAME:
     *    Size: MAX_LEN_DATA_NAME Bytes
     *    > This field indicates an existing data structure name
     *
     * ACTION:
     *    Size: MAX_LEN_ACTION_NAME bytes
     *    > This field indicates the action mapped to the data
     *    >
     *     permit
     *     deny
     *
     *
     * */

    onebyte_p_t data_name[MAX_LEN_DATA_NAME];
    onebyte_p_t action[MAX_LEN_ACTION_NAME];
};

struct policy{
    /*
     * This structure is for defining policies.
     *
     *
     * NAME:
     *   Size: MAX_LEN_POLICY_NAME Bytes
     *   > Each policy has a user defined name unique name.
     *
     * CURRENT_DATA_ACTIONS:
     *   Size: 1 Byte
     *   > This field indicates total number of data and mapped actions defined in the policy
     *
     * CONSISTENCY:
     *    Size: 1 Byte
     *    > This field indicates whether the policy in the cache is consistent with
     *      kernel module or not
     *    >
     *      Consistency: 1
     *      Inconsistency: 0
     *
     * DATA_WITH_ACTIONS:
     *    Size: sizeof(data_with_action_t)*MAX_DATA_ACTIONS_IN_POLICY Bytes
     *    > This field is an array of all data and mapped actions defined for this policy
     *
     *
     * */



    onebyte_p_t name[MAX_LEN_POLICY_NAME];
    onebyte_p_t current_data_actions;
    onebyte_p_t consistency;
    data_with_action_t data_with_actions[MAX_DATA_ACTIONS_IN_POLICY]; // 20 * 17 = 340
};

struct policy_with_int{

    /*
     * This structure is a mapping a interface to a policy.
     *
     * This structure shows which policy is going to be applied on which interface.
     *
     *   ***
     *   Policy application direction is not defined in this structure.
     *   ***
     *
     *   NAME:
     *      Size: MAX_LEN_POLICY_NAME Bytes
     *      > Each policy has a user defined name unique name.
     *
     *   INTERFACE_NAME:
     *      Size: MAX_LEN_INTERFACE_NAME Bytes
     *      > This field indicates the interface name which the policy is going to be applied
     *

     * */

    //TODO‌ interface type or code ??
    onebyte_p_t policy_name[MAX_LEN_POLICY_NAME];
    onebyte_p_t interface_name[MAX_LEN_INTERFACE_NAME];
};

struct ingress_policies{
    /*
     *
     * This Structure contains all policy_with_int structures that were defined in
     * ingress direction.
     *
     * CURRENT_INGRESS_POLICIES:
     *      Size: 1 Byte
     *      > This field indicated total number of ingress policies
     *
     *  POLICYWITHINTERFACES:
     *      Size: sizeof(policy_with_int_t) * MAX_INGRESS_POLICIES
     *      > This field is an array of policy_with_int structures
     *
     * */


    onebyte_p_t current_ingress_policies;
    policy_with_int_t policyWithInterfaces[MAX_INGRESS_POLICIES];
};

struct egress_policies{

    /*
     *
     * This Structure contains all policy_with_int structures that were defined in
     * egress direction.
     *
     * CURRENT_EGRESS_POLICIES:
     *      Size: 1 Byte
     *      > This field indicated total number of egress policies
     *
     *  POLICYWITHINTERFACES:
     *      Size: sizeof(policy_with_int_t) * MAX_EGRESS_POLICIES
     *      > This field is an array of policy_with_int structures
     *
     * */



    onebyte_p_t current_egress_policies;
    policy_with_int_t policyWithInterfaces[MAX_EGRESS_POLICIES];
};










