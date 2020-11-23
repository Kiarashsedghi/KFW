#ifndef KFW_KFW_H
#define KFW_KFW_H
#include <sys/socket.h>
#include <linux/netlink.h>

/*
 * action accept = 1
 * action drop = 0
 * */
//TODO add 1 for \0 to all strings

//GLOBAL‌ PARAMETERS
#define MAX_LEN_RULE_TYPE 10
#define MAX_LEN_RULE_VALUE 50
#define MAX_LEN_DATA_NAME 10
#define MAX_LEN_POLICY_NAME 10
#define MAX_LEN_INTERFACE_NAME 10
#define MAX_LEN_ACTION_NAME 7
#define MAX_LEN_POLICY_DIRECTION 4
#define MAX_INGRESS_POLICIES 100
#define MAX_EGRESS_POLICIES 100
#define MAX_DATA_ACTIONS_IN_POLICY 20
#define MAX_RULES_IN_DATA  10

#define MIN_SIZE_KFWP 37

#define MAX_DATA_IN_KFW  100
#define MAX_POLICY_IN_KFW 100

#define MAX_LEN_USER_COMMAND 40
#define REGEX_DATA_DEFINITION "^\\s*data\\s+[0-9a-zA-Z_]+(\\s+(any|all))?\\s*$"
#define REGEX_DATA_DELETION "^\\s*(no\\s+)data\\s+[0-9a-zA-Z_]+(\\s+(any|all))?\\s*$"

#define REGEX_RULE_DEFINITION "^\\s*(proto)\\s+(udp|tcp)\\s*$"

// TODO‌ make (value)? value part of rule for simplicity of deletion for user
#define REGEX_RULE_DELETION "^\\s*(no\\s+)(proto)\\s+(udp|tcp)\\s*$"
#define REGEX_POLICY_DEFINITION "^\\s*policy\\s+[a-zA-Z_0-9]+\\s*$"
#define REGEX_POLICY_DELETION "^\\s*(no\\s+)policy\\s+[a-zA-Z_0-9]+\\s*$"


#define REGEX_DATA_ACTION_DEFINITION "^\\s*[a-zA-Z_0-9]+\\s+(permit|deny)\\s*$"
#define REGEX_DATA_ACTION_DELETION "^\\s*(no\\s+)[a-zA-Z_0-9]+(\\s+(permit|deny))?\\s*$"

#define REGEX_QUIT_EXIT "^\\s*(quit|exit)\\s*$"
#define REGEX_BACK_TO_PREVIOUS_MODE "^\\s*back\\s*$"

#define REGEX_SHOW_DATA_COMMAND "^\\s*show\\s+data\\s+[a-zA-Z0-9_]+\\s*$"
#define REGEX_SHOW_POLICY_COMMAND "^\\s*show\\s+policy\\s+[a-zA-Z0-9_]+\\s*$"

#define REGEX_QUICK_SHOW "^\\s*\\?\\s*$"
#define REGEX_QUICK_CLEAR "^\\s*clear\\s*$"

#define REGEX_SERVICE_POLICY_DEFINITION "^\\s*service\\s+[a-zA-Z_0-9]+\\s+[a-zA-Z0-9_]+\\s+(in|out)\\s*$"
#define REGEX_SERVICE_POLICY_DELETION "^\\s*(no\\s+)service\\s+[a-zA-Z_0-9]+\\s+[a-zA-Z0-9_]+\\s+(in|out)\\s*$"


#define REGEX_SHOW_POLICIES "^\\s*show\\s+policies\\s*$"
#define REGEX_SHOW_DATAS "^\\s*show\\s+datas\\s*$"


#define REGEX_SHOW_POLICIES_WITH_DIRECTION "\\s*show\\s+policies\\s+(in|out)\\s*"

#define REGEX_SHOW_POLICIES_WITH_INTERFACE "^\\s*show\\s+policies\\s+[a-zA-Z_0-9]+\\s*$"

#define REGEX_SHOW_POLICIES_WITH_INTERFACE_DIR "^\\s*show\\s+policies\\s+[a-zA-Z_0-9]+\\s+(in|out)\\s*$"

#define REGEX_WHITESPACE "\\s+"
//


#define NETLINK_USER 31

#define MAX_LEN_KFWP_ARG1 10
#define MAX_LEN_KFWP_ARG2 32
#define MAX_LEN_KFWP_CONTEXT 10

#define LEN_kfwp_req 53


typedef signed char onebyte_np_t;
typedef unsigned char onebyte_p_t;


typedef unsigned short twobyte_p_t;
typedef signed short twobyte_np_t;


typedef struct rule rule_t;
typedef struct data data_t;
typedef struct data_with_action data_with_action_t;
typedef struct policy policy_t;
typedef struct policy_with_int policy_with_int_t;
typedef struct ingress_policies ingress_policies_t;
typedef struct egress_policies egress_policies_t;
typedef struct kfw_controls kfw_controls_t;
typedef struct regex regex__t;


typedef struct kfwp_req kfwp_req_t;
typedef struct kfwp_reply kfwp_reply_t;
typedef struct kfwp_controls kfwp_controls_t;
typedef struct consistency_flags consistency_flags_t;

struct kfwp_req{
    // kfwp was designed to exchange datas between userspace and kernel space

    onebyte_p_t type;
    onebyte_p_t arg1[MAX_LEN_KFWP_ARG1];
    onebyte_p_t arg2[MAX_LEN_KFWP_ARG2];
    onebyte_p_t context[MAX_LEN_KFWP_CONTEXT];
};

struct kfwp_reply{

    onebyte_p_t status;
    onebyte_p_t dg_cnt;
    twobyte_p_t dg_size;
};


struct consistency_flags{
    onebyte_p_t datas;
    onebyte_p_t policies;
    onebyte_p_t ingress_policies;
    onebyte_p_t egress_policies;
};


struct rule {
    onebyte_p_t type[MAX_LEN_RULE_TYPE];
    onebyte_p_t value[MAX_LEN_RULE_VALUE];
};

struct data {

    /*
     * type :
     *    all : 1
     *    any : 0 (default)
     * */
    onebyte_p_t name[MAX_LEN_DATA_NAME];
    onebyte_p_t type;
    onebyte_p_t consistency;
    onebyte_p_t current_rules;//
    rule_t rules[MAX_RULES_IN_DATA];
};

struct data_with_action{
    onebyte_p_t data_name[MAX_LEN_DATA_NAME];
    onebyte_p_t action[MAX_LEN_ACTION_NAME];
};

struct policy{
    onebyte_p_t name[MAX_LEN_POLICY_NAME];
    onebyte_p_t current_data_actions;
    onebyte_p_t consistency;
    data_with_action_t data_with_actions[MAX_DATA_ACTIONS_IN_POLICY]; // 20 * 17 = 340
};

struct policy_with_int{ // 20bytes
    onebyte_p_t policy_name[MAX_LEN_POLICY_NAME];
    onebyte_p_t interface_name[MAX_LEN_INTERFACE_NAME];   //TODO‌ interface type or code ??
};

struct ingress_policies{ // 100 * 20 = 2000bytes
    onebyte_p_t current_ingress_policies;
    policy_with_int_t policyWithInterfaces[MAX_INGRESS_POLICIES];
};

struct egress_policies{
    onebyte_p_t current_egress_policies;
    policy_with_int_t policyWithInterfaces[MAX_EGRESS_POLICIES];
};
struct regex{

    regex_t regex_quit_exit;
    regex_t regex_back_to_previous_mode;
    regex_t regex_nothing_entered;
    regex_t regex_rule_definition;
    regex_t regex_rule_deletion;
    regex_t regex_data_definition;
    regex_t regex_data_deletion;
    regex_t regex_policy_deletion;
    regex_t regex_policy_definition;
    regex_t regex_data_action_definition;
    regex_t regex_data_action_deletion;
    regex_t regex_show_data_command;
    regex_t regex_show_policy_command;

    // quick show can be issued when you are in either data definition mode or
    // policy definition
    regex_t regex_quick_show;
    regex_t regex_quick_clear;

    regex_t regex_service_policy_definition;
    regex_t regex_service_policy_deletion;


    regex_t regex_show_datas;

    regex_t regex_show_polices;
    regex_t regex_show_polices_with_dir;

    regex_t regex_show_policies_with_int;
    regex_t regex_show_policies_with_int_dir;


};

struct kfw_controls{
    ingress_policies_t ingress_policies;
    egress_policies_t  egress_policies;

    onebyte_p_t user_command[MAX_LEN_USER_COMMAND];



    //---------------------------------------------------------------------------
    /*
     * kfw should maintain some global like variables.This is because of efficiency.
     * For example , whenever user wants to create new data , we had to allocate a new data_t,
     * fill the fields of that structure and then copy it to datas array.This method gradually
     * increases memory usage , the solution can be maintaining some variables and pointers ,
     * and whenever we want to create for example a new data or a new rule , just by some definite
     * variables , handle all the operation.
     * */
    // AUX_data_st_ptr is useful when you create multiple datas.It stores the address of the next
    // available data structure in datas array so it is not necessary that for each data ,
    // you declare new variable to save its address.
    data_t *AUX_data_st_ptr;
    data_t * AUX_data_st_buff;
    onebyte_p_t AUX_data_name[MAX_LEN_DATA_NAME];
    onebyte_p_t AUX_data_type;

    policy_t *AUX_policy_st_ptr;
    onebyte_p_t AUX_policy_name[MAX_LEN_POLICY_NAME];

    data_with_action_t *AUX_data_action_st_ptr;
    onebyte_p_t AUX_action_name[MAX_LEN_ACTION_NAME];

    onebyte_p_t AUX_interface_name[MAX_LEN_INTERFACE_NAME];
    onebyte_p_t AUX_policy_direction[MAX_LEN_POLICY_DIRECTION];



    // Again like above , we have decalare some pointers and variables for rules
    rule_t *AUX_rule_st_ptr;
    onebyte_p_t AUX_rule_type[MAX_LEN_RULE_TYPE];
    onebyte_p_t AUX_rule_value[MAX_LEN_RULE_VALUE];



    //---------------------------------------------------------------------------



    onebyte_p_t current_kfw_datas;
    onebyte_p_t current_kfw_policies;
    policy_t policies[10];
    data_t datas[10];


    // AUX_functions_returns is used for holding return value of any
    // function call we have in our program
    twobyte_np_t AUX_functions_returns;






//    regex_t regex_show_data_content




};

struct kfwp_controls{

    kfwp_req_t *kfwp_msg;
    kfwp_reply_t *kfwprep_msg;

    struct sockaddr_nl src_addr, dest_addr;
    struct nlmsghdr *nlh ;
    struct iovec iov;
    int sock_fd;
    struct msghdr msg;
    onebyte_p_t kfwp_reply_first_byte;

};

//FUNCTIONS‌ PROTOTYPES
void strip_space(onebyte_p_t * str , onebyte_p_t * dst);
void setup_kfw_commands_regex(regex__t *kfwregex);
void printe(char * error_message);


void split_string_with_position(onebyte_p_t *str,onebyte_p_t position , onebyte_p_t * dst);


void split_data_definition_command(onebyte_p_t * data_def , onebyte_p_t *data_name ,onebyte_p_t *type , onebyte_p_t data_name_pos ,onebyte_p_t show_or_no_len);
void split_rule_definition_command(onebyte_p_t *rule_def,onebyte_p_t *rule_name,onebyte_p_t *rule_value , onebyte_p_t name_pos ,onebyte_p_t value_pos);
void split_policy_definition_command(onebyte_p_t *policy_def,onebyte_p_t *policy_name , onebyte_p_t name_pos ,onebyte_p_t show_or_no_len);
void split_data_with_action_command(onebyte_p_t *data_with_action_cmd,onebyte_p_t *data_name,onebyte_p_t *action , onebyte_p_t data_name_pos ,onebyte_p_t action_pos);
void split_service_policy_command(onebyte_p_t *service_policy_cmd,onebyte_p_t *policy_name,onebyte_p_t *interface_name ,onebyte_p_t * direction,
                                  onebyte_p_t policy_name_pos ,onebyte_p_t interface_name_pos,onebyte_p_t direction_pos);

onebyte_np_t get_index_of_datawithaction_in_policies(policy_t *policy , onebyte_p_t *data_name);
onebyte_np_t get_index_of_data_in_datas(kfw_controls_t *kfw_controls,onebyte_p_t *data_name);
onebyte_np_t get_index_of_rule_in_rules(data_t *data_st ,onebyte_p_t *rule_type );
onebyte_np_t get_index_of_policy_in_policies(kfw_controls_t *kfw_controls,onebyte_p_t *policy_name);
onebyte_np_t get_index_of_policyint_in_ingress(ingress_policies_t *ingressPolicies , onebyte_p_t *policy_name ,onebyte_p_t *interface_name);

onebyte_np_t get_index_of_policyint_in_egress(egress_policies_t *egressPolicies , onebyte_p_t *policy_name , onebyte_p_t*interface_name);

#endif //KFW_KFW_H
