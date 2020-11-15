#ifndef KFW_KFW_TYPES_H
#define KFW_KFW_TYPES_H

/*
 * action accept = 1
 * action drop = 0
 * */


//GLOBAL‌ PARAMETERS
#define MAX_LEN_RULE_NAME 10
#define MAX_LEN_RULE_VALUE 50
#define MAX_LEN_DATA_NAME 30
#define MAX_LEN_POLICY_NAME 30
#define MAX_LEN_INTERFACE_NAME 15
#define MAX_INGRESS_POLICIES 10
#define MAX_EGRESS_POLICIES 10
#define MAX_DATA_ACTIONS_IN_POLICY 20
#define MAX_RULES_IN_DATA  10

#define MAX_DATA_IN_KFW  100
#define MAX_POLICY_IN_KFW 100

#define MAX_LEN_USER_COMMAND 40
#define REGEX_DATA_DEFINITION "^\\s*data\\s+[0-9a-zA-Z_]+(\\s+(any|all))?\\s*$"
#define REGEX_DATA_DELETION "^\\s*(no\\s+)?data\\s+[0-9a-zA-Z_]+(\\s+(any|all))?\\s*$"

#define REGEX_RULE_DEFINITION "^\\s*(protocol)\\s+(udp|tcp)\\s*$"
#define REGEX_RULE_DELETION "^\\s*(no\\s+)?(protocol)\\s+(udp|tcp)\\s*$"
#define REGEX_POLICY_DEFINITION "^\\s*policy\\s+[a-zA-Z_0-9]+\\s*$"
#define REGEX_POLICY_DELETION "^\\s*(no\\s+)?policy\\s+[a-zA-Z_0-9]+\\s*$"


#define REGEX_DATA_ACTION_DEFINITION "^\\s*[a-zA-Z_0-9]+\\s+(permit|deny)\\s*$"
#define REGEX_QUIT_EXIT "^\\s*(quit|exit)\\s*$"
#define REGEX_BACK_TO_PREVIOUS_MODE "^\\s*back\\s*$"

#define REGEX_SHOW_DATA_COMMAND "^\\s*show\\s+data\\s+[a-zA-Z0-9_]+\\s*$"
#define REGEX_SHOW_POLICY_COMMAND "^\\s*show\\s+policy\\s+[a-zA-Z0-9_]+\\s*$"

#define REGEX_QUICK_SHOW "^\\s*\\?\\s*$"
#define REGEX_QUICK_CLEAR "^\\s*clear\\s*$"




#define REGEX_WHITESPACE "\\s+"
//



typedef unsigned char onebyte_np_t;
typedef char onebyte_p_t;


typedef unsigned short twobyte_p_t;
typedef short twobyte_np_t;


typedef struct rule rule_t;
typedef struct data data_t;
typedef struct data_with_action data_with_action_t;
typedef struct policy policy_t;
typedef struct policy_with_int policy_with_int_t;
typedef struct ingress_policies ingress_policies_t;
typedef struct egress_policies egress_policies_t;
typedef struct kfw_controls kfw_controls_t;
typedef struct regex regex__t;


struct rule {
    onebyte_p_t name[MAX_LEN_RULE_NAME];
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
    onebyte_p_t current_rules;
    rule_t rules[MAX_RULES_IN_DATA];
};

struct data_with_action{
    data_t data;
    onebyte_p_t action;
};

struct policy{
    onebyte_p_t name[MAX_LEN_POLICY_NAME];
    onebyte_p_t current_data_actions;
    data_with_action_t data_with_actions[MAX_DATA_ACTIONS_IN_POLICY];
};

struct policy_with_int{
    policy_t policy;
    onebyte_p_t interface_name[MAX_LEN_INTERFACE_NAME];   //TODO‌ interface name or code ??
};

struct ingress_policies{
    twobyte_p_t current_ingress_policies;
    policy_with_int_t policyWithInterfaces[MAX_INGRESS_POLICIES];
};

struct egress_policies{
    twobyte_p_t current_egress_policies;
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
    regex_t regex_show_data_command;
    regex_t regex_show_policy_command;
    // quick show can be issued when you are in either data definition mode or
    // policy definition
    regex_t regex_quick_show;
    regex_t regex_quick_clear;


};

struct kfw_controls{
//    ingress_policies_t ingress_policies;
//    egress_policies_t egress_policies;

    onebyte_p_t user_command[MAX_LEN_USER_COMMAND];
//    onebyte_p_t user_command_ns[1];


    // new_data is useful when you create multiple datas,
    // so it is not necessary that for each data , you declare new variable to save its address.
    data_t *new_data;

    onebyte_p_t current_kfw_datas;
    onebyte_p_t current_kfw_policies;
    policy_t policies[1];
    data_t datas[10];






//    regex_t regex_show_data_content




};



//FUNCTIONS‌ PROTOTYPES
void strip_space(onebyte_p_t * str , onebyte_p_t * dst);
void setup_kfw_commands_regex(regex__t *kfwregex);
void printe(char * error_message);
void split_data_definition_command(onebyte_p_t * data_def , onebyte_p_t *data_name ,onebyte_p_t *type );
void split_rule_definition_command(onebyte_p_t *rule_def,onebyte_p_t *rule_name,onebyte_p_t *rule_value , onebyte_p_t name_pos ,onebyte_p_t value_pos);


//



#endif //KFW_KFW_TYPES_H
