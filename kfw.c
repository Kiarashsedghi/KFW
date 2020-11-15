#include <stdio.h>
#include "string.h"
#include "regex.h"
#include "kfw_types.h"



/*
 * CLI‌ MODE
 *          global 0
 *          data_def 1
 *
 * */

int main() {


    // Initialize program by creating kfw_controls to control kfw.
    // Setting cli_mode to 0 which is global mode of kfw
    regex__t kfw_regex;
    kfw_controls_t kfw_controls;
    kfw_controls.current_kfw_datas=0;
    kfw_controls.current_kfw_policies=0;
    bzero(&(kfw_controls.user_command),MAX_LEN_USER_COMMAND);


    setup_kfw_commands_regex(&kfw_regex);





    while(1){
        printf("kfw> ");
//        bzero(kfw_controls.user_command,strlen(kfw_controls.user_command));
        fgets(kfw_controls.user_command,MAX_LEN_USER_COMMAND,stdin);


        // clear user_command for next commands
        // one copy of user_command does exist in user_command_ns

        // data definition
        if(regexec(&(kfw_regex.regex_data_definition), kfw_controls.user_command, 0, NULL, 0) ==0) {


            kfw_controls.new_data=&(kfw_controls.datas[kfw_controls.current_kfw_datas]);
            kfw_controls.new_data->type=0;
            split_data_definition_command(kfw_controls.user_command,kfw_controls.new_data->name,&kfw_controls.new_data->type);


            // update total number of datas in kfw datas
            kfw_controls.current_kfw_datas++;

            while(1) {
                printf("kfw-data> ");
                fgets(kfw_controls.user_command, MAX_LEN_USER_COMMAND, stdin);

                //rule_definition
                if (regexec(&kfw_regex.regex_rule_definition, kfw_controls.user_command, 0, NULL, 0) == 0) {
                    rule_t *new_rule = &(kfw_controls.new_data->rules[kfw_controls.new_data->current_rules]);

                    split_rule_definition_command(kfw_controls.user_command, new_rule->name, new_rule->value, 0, 1);

                    //update total number of rules in data
                    kfw_controls.new_data->current_rules++;

                    printf("rule added \n");
                }
                    // rule deletion
                else if (regexec(&kfw_regex.regex_rule_deletion, kfw_controls.user_command, 0, NULL, 0) == 0) {
                    onebyte_p_t rule_name[MAX_LEN_RULE_NAME];
                    onebyte_p_t rule_value[MAX_LEN_RULE_VALUE];
                    bzero(rule_name, MAX_LEN_RULE_NAME);
                    bzero(rule_value, MAX_LEN_RULE_VALUE);

                    split_rule_definition_command(kfw_controls.user_command, rule_name, rule_value, 1, 2);
                    //TODO‌ write the logic of deletion
                    for (int i = 0; i < kfw_controls.new_data->current_rules; i++)
                        if (strcmp(kfw_controls.new_data->rules[i].name, rule_name) == 0 &&
                            strcmp(kfw_controls.new_data->rules[i].value, rule_value) == 0) {
                            if (i == kfw_controls.new_data->current_rules - 1)
                                kfw_controls.new_data->current_rules--;
                            else {
                                i++;
                                while (i <= kfw_controls.new_data->current_rules - 1) {
                                    memcpy(&kfw_controls.new_data->rules[i - 1], &kfw_controls.new_data->rules[i], sizeof(rule_t));
                                    i++;
                                }
                            }
                            break;
                        }
                    kfw_controls.new_data->current_rules--;
                    printf("rule removed \n");
                }

                    // quick clear
                else if (regexec(&kfw_regex.regex_quick_clear, kfw_controls.user_command, 0, NULL, 0) == 0) {
                    bzero(kfw_controls.new_data->rules, (kfw_controls.new_data->current_rules) * sizeof(rule_t));
                    kfw_controls.new_data->current_rules = 0;
                }
                    // quick  show
                else if (regexec(&kfw_regex.regex_quick_show, kfw_controls.user_command, 0, NULL, 0) == 0) {
                    for (int i = 0; i < kfw_controls.new_data->current_rules; i++) {
                        printf("%s %s\n", kfw_controls.new_data->rules[i].name, kfw_controls.new_data->rules[i].value);

                    }
                }
                else if (regexec(&kfw_regex.regex_back_to_previous_mode, kfw_controls.user_command, 0, NULL, 0) == 0) {
                        break;
                }


                }

        }
        // policy definition
        else if(regexec(&kfw_regex.regex_policy_definition, kfw_controls.user_command, 0, NULL, 0) ==0){
            // create policy structure with type default or specified //TODO‌ ?
            while(1) {
                printf("kfw-policy> ");
                fgets(kfw_controls.user_command, MAX_LEN_USER_COMMAND, stdin);

                if (regexec(&kfw_regex.regex_data_action_definition, kfw_controls.user_command, 0, NULL, 0) == 0) {
                    printf("data detected\n");
                } else if (regexec(&kfw_regex.regex_back_to_previous_mode, kfw_controls.user_command, 0, NULL, 0) ==0) {
                    break;
                }
                else if (regexec(&kfw_regex.regex_quick_show, kfw_controls.user_command, 0, NULL, 0) ==0) {
                    printf("quick show issued \n");
                }
                else if (regexec(&kfw_regex.regex_quick_clear, kfw_controls.user_command, 0, NULL, 0) ==0) {
                    printf("quick clear issued \n");
                }


                // clear user_command for next commands
                // one copy of user_command does exist in user_command_ns
                bzero(kfw_controls.user_command, strlen(kfw_controls.user_command));

            }

        }


        // data deletion
        else if(regexec(&kfw_regex.regex_data_deletion, kfw_controls.user_command, 0, NULL, 0) ==0) {
            // when remove data check policy dependency
            printf("data deletion issued");
        }

        // policy deletion
        else if(regexec(&kfw_regex.regex_policy_deletion, kfw_controls.user_command, 0, NULL, 0) ==0) {
                printf("policy deletion issued");
        }


        // show data
        else if (regexec(&kfw_regex.regex_show_data_command, kfw_controls.user_command, 0, NULL, 0) ==0){
            printf("show data issued\n");
        }

        // show policy
        else if (regexec(&kfw_regex.regex_show_policy_command, kfw_controls.user_command, 0, NULL, 0) ==0){
            printf("show policy issued\n");
        }

        // quit / exit
        else if (regexec(&kfw_regex.regex_quit_exit, kfw_controls.user_command, 0, NULL, 0) ==0){
            printf("Bye!!\n");
            return 0;
        }




//        else if(strlen(kfw_controls.user_command)==0){
//            printf("inja\n"); //TODO
//            continue;
//        }
//        else{
//            printe("Ambiguous command");
//
//        }

}




    return 0;
}

void split_rule_definition_command(onebyte_p_t *rule_def,onebyte_p_t *rule_name,onebyte_p_t *rule_value , onebyte_p_t name_pos ,onebyte_p_t value_pos){
    onebyte_p_t rule_command_ele=-1;
    onebyte_p_t *temp;
    while(*rule_def){
        if(*rule_def==32 || *rule_def==10 || *rule_def==9)
            rule_def++;
        else{
            rule_command_ele++;
            if(rule_command_ele==0 && name_pos==1)
                rule_def+=2;
            else if(rule_command_ele==name_pos){
                temp=rule_def;
                while(*rule_def!=32 && *rule_def!=10 && *rule_def!=9)
                    rule_def++;
                memcpy(rule_name,temp,rule_def-temp);
            }
            else if(rule_command_ele==value_pos){
                temp=rule_def;
                while(*rule_def!=32 && *rule_def!=10 && *rule_def!=9)
                    rule_def++;
                memcpy(rule_value,temp,rule_def-temp);
                // we put break to end the function at this point because
                // we have collected all the things we need
                break;
            }

        }


    }


}

void split_data_definition_command(onebyte_p_t * data_def , onebyte_p_t *data_name ,onebyte_p_t *type ){
    onebyte_p_t data_command_ele=0;
    onebyte_p_t *temp;
    while(*data_def){
        if(*data_def==32 || *data_def==10 || *data_def==9)
            data_def++;
        else{
            data_command_ele++;
            if(data_command_ele==1)
                data_def+=4;
            else if(data_command_ele==2){
                temp=data_def;
                while(*data_def!=32 && *data_def!=10 && *data_def!=9)
                    data_def++;
                memcpy(data_name,temp,data_def-temp);
            }
            else if(data_command_ele==3){
                if(strncmp(data_def,"all",3)==0) {
                    *type = 1;
                    // break to finish the function
                    break;
                }
            }

        }


    }

}

void setup_kfw_commands_regex(regex__t *kfwregex){
    //TODO‌ we need exit code
    if (regcomp(&kfwregex->regex_data_definition,REGEX_DATA_DEFINITION,REG_EXTENDED) != 0) {
        printe("data_definition regex compilation error");
    }
    if (regcomp(&kfwregex->regex_policy_definition,REGEX_POLICY_DEFINITION,REG_EXTENDED) != 0) {
        printe("policy_definition regex compilation error");
    }
    if (regcomp(&kfwregex->regex_data_deletion,REGEX_DATA_DELETION,REG_EXTENDED) != 0) {
        printe("data_deletion regex compilation error");
    }
    if (regcomp(&kfwregex->regex_policy_deletion,REGEX_POLICY_DELETION,REG_EXTENDED) != 0) {
        printe("policy_deletion regex compilation error");
    }



    if (regcomp(&kfwregex->regex_data_action_definition,REGEX_DATA_ACTION_DEFINITION,REG_EXTENDED) != 0) {
        printe("data_action regex compilation error");
    }
    if (regcomp(&kfwregex->regex_policy_definition,REGEX_POLICY_DEFINITION,REG_EXTENDED) != 0) {
        printe("policy_definition regex compilation error");
    }
    if (regcomp(&kfwregex->regex_data_action_definition,REGEX_DATA_ACTION_DEFINITION,REG_EXTENDED) != 0) {
        printe("data_action_definition regex compilation error");
    }
    if (regcomp(&kfwregex->regex_quit_exit,REGEX_QUIT_EXIT,REG_EXTENDED) != 0) {
        printe("quit_exit regex compilation error");
    }
    if (regcomp(&kfwregex->regex_rule_definition,REGEX_RULE_DEFINITION,REG_EXTENDED) != 0) {
        printe("rule_definition regex compilation error");
    }
    if (regcomp(&kfwregex->regex_rule_deletion,REGEX_RULE_DELETION,REG_EXTENDED) != 0) {
        printe("rule_deletion regex compilation error");
    }



    if (regcomp(&kfwregex->regex_back_to_previous_mode,REGEX_BACK_TO_PREVIOUS_MODE,REG_EXTENDED) != 0) {
        printe("back_to_previous_mode regex compilation error");
    }
    if (regcomp(&kfwregex->regex_nothing_entered,REGEX_WHITESPACE,REG_EXTENDED) != 0) {
        printe("white_space regex compilation error");
    }
    if (regcomp(&kfwregex->regex_show_data_command,REGEX_SHOW_DATA_COMMAND,REG_EXTENDED) != 0) {
        printe("show_data regex compilation error");
    }
    if (regcomp(&kfwregex->regex_show_policy_command,REGEX_SHOW_POLICY_COMMAND,REG_EXTENDED) != 0) {
        printe("show_policy regex compilation error");
    }
    if (regcomp(&kfwregex->regex_quick_show,REGEX_QUICK_SHOW,REG_EXTENDED) != 0) {
        printe("quick_show regex compilation error");
    }
    if (regcomp(&kfwregex->regex_quick_clear,REGEX_QUICK_CLEAR,REG_EXTENDED) != 0) {
        printe("quick_clear regex compilation error");
    }


}


void strip_space(onebyte_p_t * str , onebyte_p_t * dst){
    /*
     * This function is designed to strip spaces around any input‌(usuall user command)
     *
     * */

    char *beg_no_space=str;
    char *end_no_space=str;

    bzero(dst,strlen(dst));

    while(*end_no_space)
        end_no_space++;
    end_no_space--;

    while(*beg_no_space==32 ||*beg_no_space==10|| *beg_no_space==9 )
        beg_no_space++;

    while(*end_no_space==32  ||*end_no_space==10 || *end_no_space==9)
        end_no_space--;

    memcpy(dst,beg_no_space,end_no_space-beg_no_space+1);

}


void printe(char * error_message){
    /*
     * This function will print error message with red color
     * */
    printf("\033[1;31m");
    printf("ERR<200c>: %s\n",error_message);
    printf("\033[0m");
}