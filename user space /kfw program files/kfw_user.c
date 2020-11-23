/*
 *
 *  THIS FILE CONTAINS KFW MAIN PROGRAM
 *
 *
 *
 *  Written By :  Kiarash Sedghi
 *
 *
 * */

#include <stdio.h>
#include "string.h"
#include "regex.h"
#include "kfw_user.h"
#include "kfw_user_functions.h"


#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wpointer-sign"




int main() {


    ingress_policies_t ingress_policies;
    egress_policies_t egress_policies;

    consistency_flags_t consistencyFlags;
    consistencyFlags.data_cache=0;
    consistencyFlags.policy_cache=0;
    consistencyFlags.ingress_policy_cache=0;
    consistencyFlags.egress_policy_cache=0;

    // Initialize program by creating kfw_controls to control kfw.
    // Setting cli_mode to 0 which is global mode of kfw
    regex__t kfw_regex;
    kfw_controls_t kfw_controls;
    kfw_controls.current_kfw_datas=0;
    kfw_controls.current_kfw_policies=0;
    bzero(&(kfw_controls.user_command),MAX_LEN_USER_COMMAND);

    // clearing kfw_controls.AUX_data_name
    bzero(kfw_controls.AUX_data_name,MAX_LEN_DATA_NAME);

    // clearing kfw_controls.AUX_policy_name
    bzero(kfw_controls.AUX_policy_name,MAX_LEN_POLICY_NAME);

    bzero(kfw_controls.AUX_policy_direction,MAX_LEN_POLICY_DIRECTION);
    bzero(kfw_controls.AUX_interface_name,MAX_LEN_INTERFACE_NAME);

    bzero(kfw_controls.AUX_rule_type,MAX_LEN_RULE_TYPE);
    bzero(kfw_controls.AUX_rule_type,MAX_LEN_RULE_VALUE);


    compile_kfw_cmds_regexes(&kfw_regex);

    //---------connecting to kernel-------------
    kfwp_controls_t kfwp_controls;



    // Connection --------------------------------


    while(1){
        printf("kfw> ");
        fgets(kfw_controls.user_command,MAX_LEN_USER_COMMAND,stdin);

        // data definition
        if(regexec(&(kfw_regex.regex_data_definition), kfw_controls.user_command, 0, NULL, 0) ==0) {

            /*
             * When user issues ( data DATA_NAME ) , first we should check our datas_cache cache.
             * If we found a data , we then check its consistency with kernel module.
             *  if it was consistent , it is ok.
             *  else we send kfwp request
             *
             * Else we send kfwp request
             * */


            split_data_def_del_cmd(kfw_controls.user_command, kfw_controls.AUX_data_name, &kfw_controls.AUX_data_type,
                                   1, 0);


            // check existence of a data with name specified by command which is stored in AUX_data_name.
            // If it does exist we get index of it , else we get -1.
            kfw_controls.AUX_functions_returns= getindex_data_in_data_cache(&kfw_controls, kfw_controls.AUX_data_name);


            // A data with type AUX_data_name does not exist so we send kfwp request to kernel
            // to create new one
            if(kfw_controls.AUX_functions_returns == -1){
                printf("new\n");
                kfw_controls.AUX_data_st_ptr=&kfw_controls.datas_cache[kfw_controls.current_kfw_datas];

                kfw_controls.AUX_functions_returns= talk_2_module(NULL, &kfw_controls, &kfwp_controls, 0b00000000,
                                                                  kfw_controls.AUX_data_name,
                                                                  &kfw_controls.AUX_data_type,
                                                                  NULL, kfw_controls.AUX_data_st_ptr, NULL, NULL,
                                                                  NULL);


                printf("bytes:%d\n",kfw_controls.AUX_functions_returns);
                // if we had bytes written to that address
                if(kfw_controls.AUX_functions_returns !=0){
                    kfw_controls.AUX_data_st_ptr->consistency=1;
                    kfw_controls.current_kfw_datas++;
                }

                else
                    kfw_controls.AUX_data_st_ptr=NULL;


                // set datas_cache array consistancy to 0 because a new data
                // was created
                consistencyFlags.data_cache=1;

            }
            else {
                printf("exist on cache\n");


                printf("chera %d",kfw_controls.datas_cache[kfw_controls.AUX_functions_returns].consistency);
                if(kfw_controls.datas_cache[kfw_controls.AUX_functions_returns].consistency == 1){
                    /* We should check whether data_type specified by user_command matches
                     * data_type of the data we have found.
                     *
                     * Users Cannot change the type whenever they enter data definition mode.
                    */
                    if(kfw_controls.datas_cache[kfw_controls.AUX_functions_returns].type != kfw_controls.AUX_data_type){
                        printe("Cannot change type for data %s\nTo change the type first delete the type and recreate it"); //TODO‌
                        continue;
                    }
                    else
                        kfw_controls.AUX_data_st_ptr = &(kfw_controls.datas_cache[kfw_controls.AUX_functions_returns]);
                }
                else{
                    printf("consistency was failed / send request to kernel\n");
                    kfw_controls.AUX_data_st_ptr=&kfw_controls.datas_cache[kfw_controls.current_kfw_datas];

                    kfw_controls.AUX_functions_returns= talk_2_module(NULL, &kfw_controls, &kfwp_controls,
                                                                      0b00000000,
                                                                      kfw_controls.AUX_data_name,
                                                                      &kfw_controls.AUX_data_type, NULL,
                                                                      kfw_controls.AUX_data_st_ptr, NULL, NULL, NULL);

                    kfw_controls.AUX_data_st_ptr->consistency=1;

                    if(kfw_controls.AUX_functions_returns==0)
                        kfw_controls.AUX_data_st_ptr->current_rules=0;

                    // set datas_cache array consistancy to 0 because the data probable
                    // changed //TODO
                    consistencyFlags.data_cache=0;

                }


            }


            while(1) {
                printf("kfw-data> ");
                // Clear the user command.Make all the written bytes zero
                bzero(kfw_controls.user_command,strlen(kfw_controls.user_command));
                fgets(kfw_controls.user_command, MAX_LEN_USER_COMMAND, stdin);

                //rule_definition(with overwrite ability)
                if (regexec(&kfw_regex.regex_rule_definition, kfw_controls.user_command, 0, NULL, 0) == 0) {


                    /* split rule command and put the type and value of the rule to
                     *  rules array of (founded/created) data which are :
                     *         kfw_controls.AUX_rule_type
                     *         kfw_controls.AUX_rule_value
                    */
                    bzero(kfw_controls.AUX_rule_type, strlen(kfw_controls.AUX_rule_type));
                    split_rule_def_del_cmd(kfw_controls.user_command, kfw_controls.AUX_rule_type,
                                           kfw_controls.AUX_rule_value, 0, 1);

                    printf("%s\n", kfw_controls.AUX_data_name);
                    // send request for the rule
                    talk_2_module(NULL, &kfw_controls, &kfwp_controls, 0b00000001, kfw_controls.AUX_rule_type,
                                  kfw_controls.AUX_rule_value, kfw_controls.AUX_data_name,
                                  &kfw_controls.datas_cache[kfw_controls.AUX_functions_returns], NULL, NULL, NULL);

                    printf("rule sent\n");


                    //set consistency flag to 0
                    if(kfw_controls.AUX_data_st_ptr!=NULL) {
                        kfw_controls.AUX_data_st_ptr->consistency = 0;
                        printf("inconsistent\n");
                    }

                    // set datas_cache array consistancy to 0
                    consistencyFlags.data_cache=0;


                }
                // rule deletion
                else if (regexec(&kfw_regex.regex_rule_deletion, kfw_controls.user_command, 0, NULL, 0) == 0) {

                    onebyte_p_t rule_type[MAX_LEN_RULE_TYPE];
                    onebyte_p_t rule_value[MAX_LEN_RULE_VALUE];
                    bzero(rule_type, MAX_LEN_RULE_TYPE);
                    bzero(rule_value, MAX_LEN_RULE_VALUE);

                    split_rule_def_del_cmd(kfw_controls.user_command, rule_type, rule_value, 1, 2);


                    // send request to kernel
                    talk_2_module(NULL, &kfw_controls, &kfwp_controls, 0b10000001, kfw_controls.AUX_rule_type,
                                  kfw_controls.AUX_rule_value, kfw_controls.AUX_data_name,
                                  &kfw_controls.datas_cache[kfw_controls.AUX_functions_returns], NULL, NULL, NULL);

                    //set consistency flag to 0
                    if(kfw_controls.AUX_data_st_ptr!=NULL) {
                        kfw_controls.AUX_data_st_ptr->consistency = 0;
                        printf("inconsistent\n");
                    }
                    // set datas_cache array consistancy to 0
                    consistencyFlags.data_cache=0;

                }

                    // quick clear
                else if (regexec(&kfw_regex.regex_quick_clear, kfw_controls.user_command, 0, NULL, 0) == 0) {
                    // send request to kernel // TODO‌ arg1 arg2 not necessary
                    talk_2_module(NULL, &kfw_controls, &kfwp_controls, 0b01111110, "NULL", "NULL", "NULL", NULL,
                                  NULL,
                                  NULL, NULL);

                    //set consistency flag to 0
                    if(kfw_controls.AUX_data_st_ptr!=NULL) {
                        kfw_controls.AUX_data_st_ptr->consistency = 0;
                        printf("inconsistent\n");
                    }
                    // set datas_cache array consistancy to 0
                    consistencyFlags.data_cache=0;

                }

                    // quick  show
                else if (regexec(&kfw_regex.regex_quick_show, kfw_controls.user_command, 0, NULL, 0) == 0) {

                    printf("quick show issued\n");

                    if(kfw_controls.AUX_data_st_ptr!=NULL){
                        printf("mokhaledf\n");
                        if(kfw_controls.AUX_data_st_ptr->consistency==1){
                        printf("reading from cache consitent data%d\n",kfw_controls.AUX_data_st_ptr->current_rules);
                        for (int i = 0; i < kfw_controls.AUX_data_st_ptr->current_rules; i++) {
                            printf("%s %s\n", kfw_controls.AUX_data_st_ptr->rules[i].type, kfw_controls.AUX_data_st_ptr->rules[i].value);
                            }
                        }
                        else{
                        // send request to kernel
                        kfw_controls.AUX_functions_returns= talk_2_module(NULL, &kfw_controls, &kfwp_controls,
                                                                          0b00000000,
                                                                          kfw_controls.AUX_data_name,
                                                                          &kfw_controls.AUX_data_type, NULL,
                                                                          kfw_controls.AUX_data_st_ptr, NULL, NULL,
                                                                          NULL);

                        kfw_controls.AUX_data_st_ptr->consistency=1;

                            // update cache if does not consistent with kernel
                        if(kfw_controls.AUX_functions_returns==0)
                            kfw_controls.AUX_data_st_ptr->current_rules=0;
                        else
                            for(int i = 0; i < kfw_controls.AUX_data_st_ptr->current_rules; i++) {
                                printf("%s %s\n", kfw_controls.AUX_data_st_ptr->rules[i].type, kfw_controls.AUX_data_st_ptr->rules[i].value);
                            }
                    }

                }else{
                        printf("pointer is null\n");
                        // send request to kernel
                        kfw_controls.AUX_functions_returns= talk_2_module(NULL, &kfw_controls, &kfwp_controls,
                                                                          0b00000000,
                                                                          kfw_controls.AUX_data_name,
                                                                          &kfw_controls.AUX_data_type, NULL,
                                                                          kfw_controls.AUX_data_st_ptr, NULL, NULL,
                                                                          NULL);
                        printf("%d\n",kfw_controls.AUX_functions_returns);



                        // update cache if exist and if does not consistent with kernel
                        if(kfw_controls.AUX_data_st_ptr!=NULL){
                            kfw_controls.AUX_data_st_ptr->consistency=1;


                            if(kfw_controls.AUX_functions_returns==0)
                                kfw_controls.AUX_data_st_ptr->current_rules=0;
                            else
                                for(int i = 0; i < kfw_controls.AUX_data_st_ptr->current_rules; i++) {
                                    printf("%s %s\n", kfw_controls.AUX_data_st_ptr->rules[i].type, kfw_controls.AUX_data_st_ptr->rules[i].value);
                                }
                        }
                }

                }

                    // issuing back
                else if (regexec(&kfw_regex.regex_back_to_previous_mode, kfw_controls.user_command, 0, NULL, 0) == 0) {
                    break;
                }
            }
        }

        // policy definition
        else if(regexec(&kfw_regex.regex_policy_definition, kfw_controls.user_command, 0, NULL, 0) ==0){

            // clear kfw_controls.AUX_policy_name for new name
            bzero(kfw_controls.AUX_policy_name,strlen(kfw_controls.AUX_policy_name));
            split_policy_def_del_show_cmd(kfw_controls.user_command, kfw_controls.AUX_policy_name, 1, 0);


            kfw_controls.AUX_functions_returns= getindex_policy_in_policy_cache(&kfw_controls,
                                                                                kfw_controls.AUX_policy_name);


            // A policy with name AUX_policy_name does not exist so we allocate new one in
            // kfw_controls.policies_cache
            if(kfw_controls.AUX_functions_returns == -1){

                printf("policy not exist on cache\n");

                printf("send request\n");

                kfw_controls.AUX_policy_st_ptr=&kfw_controls.policies_cache[kfw_controls.current_kfw_policies];

                kfw_controls.AUX_functions_returns= talk_2_module(NULL, &kfw_controls, &kfwp_controls, 0b00000010,
                                                                  kfw_controls.AUX_policy_name, NULL, NULL, NULL,
                                                                  kfw_controls.AUX_policy_st_ptr, NULL, NULL);


                printf("policy bytes:%d\n",kfw_controls.AUX_functions_returns);

                // if we had bytes written to that address
                if(kfw_controls.AUX_functions_returns !=0)
                    kfw_controls.current_kfw_policies++;
                else
                    kfw_controls.AUX_policy_st_ptr=NULL;

                // set policies_cache array consistancy to 0 because the policy probabaly
                // created/entered with no data
                consistencyFlags.policy_cache=0;

            }
            else {
                printf("policy exist on cache\n");

                if(kfw_controls.policies_cache[kfw_controls.AUX_functions_returns].consistency == 1){

                        kfw_controls.AUX_policy_st_ptr = &(kfw_controls.policies_cache[kfw_controls.AUX_functions_returns]);
                }
                else{
                    printf("consistency was failed / send request to kernel\n");

                    kfw_controls.AUX_policy_st_ptr=&kfw_controls.policies_cache[kfw_controls.current_kfw_policies];

                    talk_2_module(NULL, &kfw_controls, &kfwp_controls, 0b00000010, kfw_controls.AUX_policy_name,
                                  NULL,
                                  NULL, NULL, kfw_controls.AUX_policy_st_ptr, NULL, NULL);

                    kfw_controls.AUX_policy_st_ptr->consistency=1;

                    // set policies_cache array consistancy to 0 because the policy probabaly
                    // changed
                    consistencyFlags.policy_cache=0;


                }

            }


            while(1) {
                printf("kfw-policy> ");
                // Clear the user command.Make all the written bytes zero
                bzero(kfw_controls.user_command,strlen(kfw_controls.user_command));

                fgets(kfw_controls.user_command, MAX_LEN_USER_COMMAND, stdin);

                // data_action definition( with overwrite ability )
                if (regexec(&kfw_regex.regex_data_action_definition, kfw_controls.user_command, 0, NULL, 0) == 0) {
                    split_data_action_def_del_cmd(kfw_controls.user_command, kfw_controls.AUX_data_name,
                                                  kfw_controls.AUX_action_name, 0, 1);


                    talk_2_module(NULL, &kfw_controls, &kfwp_controls, 0b00000011, kfw_controls.AUX_data_name,
                                  kfw_controls.AUX_action_name, "NULL",
                                  NULL, &kfw_controls.policies_cache[kfw_controls.AUX_functions_returns], NULL, NULL);



                    printf("data with action sent\n");

                    //set consistency flag to 0
                    if(kfw_controls.AUX_policy_st_ptr!=NULL) {
                        kfw_controls.AUX_policy_st_ptr->consistency = 0;
                        printf("inconsistent\n");
                    }

                    // set policies_cache array consistancy to 0 because the policy probabaly
                    // changed
                    consistencyFlags.policy_cache=0;

                }

                else if (regexec(&kfw_regex.regex_back_to_previous_mode, kfw_controls.user_command, 0, NULL, 0) ==0) {
                    break;
                }

                    // data_action deletion
                else if (regexec(&kfw_regex.regex_data_action_deletion, kfw_controls.user_command, 0, NULL, 0) ==0) {

                    split_data_action_def_del_cmd(kfw_controls.user_command, kfw_controls.AUX_data_name,
                                                  kfw_controls.AUX_action_name, 1, 2);


                    talk_2_module(NULL, &kfw_controls, &kfwp_controls, 0b10000011, kfw_controls.AUX_data_name,
                                  kfw_controls.AUX_action_name, "NULL",
                                  NULL, &kfw_controls.policies_cache[kfw_controls.AUX_functions_returns], NULL, NULL);

                    //set consistency flag to 0
                    if(kfw_controls.AUX_policy_st_ptr!=NULL) {
                        kfw_controls.AUX_policy_st_ptr->consistency = 0;
                        printf("inconsistent\n");
                    }
                    // set policies_cache array consistancy to 0 because the policy probabaly
                    // changed
                    consistencyFlags.policy_cache=0;


                }

                // quick show
                else if (regexec(&kfw_regex.regex_quick_show, kfw_controls.user_command, 0, NULL, 0) ==0) {

                    printf("quick show issued for policy\n");

                    if(kfw_controls.AUX_policy_st_ptr!=NULL){
                        printf("mokhaledf .. %d\n",kfw_controls.AUX_policy_st_ptr->consistency);
                        if(kfw_controls.AUX_policy_st_ptr->consistency==1){
                            printf("reading from cache consitent policy%d\n",kfw_controls.AUX_policy_st_ptr->current_data_actions);
                            for(int i = 0; i < kfw_controls.AUX_policy_st_ptr->current_data_actions; i++) {
                                printf("%s %s\n", kfw_controls.AUX_policy_st_ptr->data_with_actions[i].data_name, kfw_controls.AUX_policy_st_ptr->data_with_actions[i].action);
                            }
                        }
                        else{
                            printf("cache is not consistent , send reques\n");
                            // send request to kernel
                            kfw_controls.AUX_functions_returns= talk_2_module(NULL, &kfw_controls, &kfwp_controls,
                                                                              0b00000010, kfw_controls.AUX_data_name,
                                                                              &kfw_controls.AUX_data_type, NULL,
                                                                              NULL,
                                                                              kfw_controls.AUX_policy_st_ptr, NULL,
                                                                              NULL);

                            kfw_controls.AUX_policy_st_ptr->consistency=1;

                            // update cache if does not consistent with kernel
                            if(kfw_controls.AUX_functions_returns==0)
                                kfw_controls.AUX_policy_st_ptr->current_data_actions=0;
                            else
                                for(int i = 0; i < kfw_controls.AUX_policy_st_ptr->current_data_actions; i++) {
                                    printf("%s %s\n", kfw_controls.AUX_policy_st_ptr->data_with_actions[i].data_name, kfw_controls.AUX_policy_st_ptr->data_with_actions[i].action);
                                }
                        }

                    }else{
                        printf("pointer is null\n");
                        // send request to kernel
                        kfw_controls.AUX_functions_returns= talk_2_module(NULL, &kfw_controls, &kfwp_controls,
                                                                          0b00000010,
                                                                          kfw_controls.AUX_data_name,
                                                                          &kfw_controls.AUX_data_type, NULL, NULL,
                                                                          kfw_controls.AUX_policy_st_ptr, NULL, NULL);
                        printf("%d\n",kfw_controls.AUX_functions_returns);
                        // update cache if exist and if does not consistent with kernel
                        if(kfw_controls.AUX_policy_st_ptr!=NULL){

                            kfw_controls.AUX_policy_st_ptr->consistency=1;

                            if(kfw_controls.AUX_functions_returns==0)
                                kfw_controls.AUX_policy_st_ptr-> current_data_actions=0;
                            else
                                for(int i = 0; i < kfw_controls.AUX_policy_st_ptr->current_data_actions; i++) {
                                    printf("%s %s\n", kfw_controls.AUX_policy_st_ptr->data_with_actions[i].data_name, kfw_controls.AUX_policy_st_ptr->data_with_actions[i].action);
                                }
                        }
                    }

                }
                    // quick clear
                else if (regexec(&kfw_regex.regex_quick_clear, kfw_controls.user_command, 0, NULL, 0) ==0) {
                    // send request to kernel // TODO‌ arg1 arg2 not necessary
                    talk_2_module(NULL, &kfw_controls, &kfwp_controls, 0b01111111, "NULL", "NULL", "NULL", NULL,
                                  NULL,
                                  NULL, NULL);

                    //set consistency flag to 0
                    if(kfw_controls.AUX_policy_st_ptr!=NULL) {
                        kfw_controls.AUX_policy_st_ptr->consistency = 0;
                        printf("inconsistent\n");
                    }
                    // set policies_cache array consistancy to 0 because the policy probabaly
                    // changed
                    consistencyFlags.policy_cache=0;


//
//                    // For quick clear , we just make total number of data_with_actions to zero.
//                    // The first implementation was to make all the bytes of data_with_actions array zero ,
//                    // but for efficiency purposes it was ignored.
//                    kfw_controls.AUX_policy_st_ptr->current_data_actions = 0;
//                    printf("quick clear issued \n");
//                    // bzero for clear
                }

            }

        }

        // data deletion
        else if(regexec(&kfw_regex.regex_data_deletion, kfw_controls.user_command, 0, NULL, 0) ==0) {
            /*#TODO important
             * Data deletion command acceptance:
             *          no data DATA_NAME (all/any)?   * specifying (any/all) is optional and does not effect deletion
             *
             * */

            // when remove data check policy dependency
            split_data_def_del_cmd(kfw_controls.user_command, kfw_controls.AUX_data_name, &kfw_controls.AUX_data_type,
                                   2, 2);

            // send deletion request to kernel
            kfw_controls.AUX_functions_returns= talk_2_module(NULL, &kfw_controls, &kfwp_controls, 0b10000000,
                                                              kfw_controls.AUX_data_name,
                                                              &kfw_controls.AUX_data_type,
                                                              NULL, NULL, NULL, NULL, NULL);


            // when we delete the data from cache
            // we do not change datas_cache array consistancy flag
            // thats because we don't see any request be generated by kfw

            // successful deletion of data in kernel
            if(kfw_controls.AUX_functions_returns==0){
                kfw_controls.AUX_functions_returns= getindex_data_in_data_cache(&kfw_controls,
                                                                                kfw_controls.AUX_data_name);

                if(kfw_controls.AUX_functions_returns != -1){
                    // Delte the data from the cache
                    // Delete the data from datas_cache array.
                    // Deletion policy is same as before.
                    if(kfw_controls.AUX_functions_returns == kfw_controls.current_kfw_datas - 1) {
                        if (kfw_controls.current_kfw_datas - 1 != -1)
                            kfw_controls.current_kfw_datas--;
                    }
                    else{
                        kfw_controls.AUX_functions_returns++;
                        while(kfw_controls.AUX_functions_returns <= kfw_controls.current_kfw_datas - 1){
                            memcpy(&kfw_controls.datas_cache[kfw_controls.AUX_functions_returns - 1], &kfw_controls.datas_cache[kfw_controls.AUX_functions_returns], sizeof(data_t));
                            kfw_controls.AUX_functions_returns++;
                        }
                        //update total number of datas_cache
                        kfw_controls.current_kfw_datas--;
                        printf("data deletion issued");
                    }
                }
            }
        }

        // policy deletion
        else if(regexec(&kfw_regex.regex_policy_deletion, kfw_controls.user_command, 0, NULL, 0) ==0) {

            //TODO check dependency of ingress / egress
            // clear kfw_controls.AUX_policy_name for new name
            bzero(kfw_controls.AUX_policy_name,strlen(kfw_controls.AUX_policy_name));
            split_policy_def_del_show_cmd(kfw_controls.user_command, kfw_controls.AUX_policy_name, 2, 2);


            kfw_controls.AUX_functions_returns= talk_2_module(NULL, &kfw_controls, &kfwp_controls, 0b10000010,
                                                              kfw_controls.AUX_policy_name, NULL, NULL, NULL, NULL,
                                                              NULL,
                                                              NULL);



            kfw_controls.AUX_functions_returns= getindex_policy_in_policy_cache(&kfw_controls,
                                                                                kfw_controls.AUX_policy_name);

            // deletion policy is same as before
            if(kfw_controls.AUX_functions_returns != -1){
                if(kfw_controls.AUX_functions_returns == kfw_controls.current_kfw_policies - 1) {
                    if(kfw_controls.current_kfw_policies-1!=-1)
                        kfw_controls.current_kfw_policies--;


                }
                else{
                    kfw_controls.AUX_functions_returns++;
                    while(kfw_controls.AUX_functions_returns <= kfw_controls.current_kfw_policies - 1){
                        memcpy(&kfw_controls.policies_cache[kfw_controls.AUX_functions_returns - 1], &kfw_controls.policies_cache[kfw_controls.AUX_functions_returns], sizeof(policy_t));
                        kfw_controls.AUX_functions_returns++;
                    }
                    //update total number of policies_cache
                    kfw_controls.current_kfw_policies--;
                }

                printf("del<%s>\n",kfw_controls.AUX_policy_name);

                printf("policy deletion issued\n");
            }


        }

        // show data DATA_NAME
        else if (regexec(&kfw_regex.regex_show_data_command, kfw_controls.user_command, 0, NULL, 0) ==0){
            //TODO‌ IMPORTATN
            // show data DATA_NAME (all/any)>not important

            split_data_def_del_cmd(kfw_controls.user_command, kfw_controls.AUX_data_name, &kfw_controls.AUX_data_type,
                                   2, 4);

            kfw_controls.AUX_functions_returns= getindex_data_in_data_cache(&kfw_controls, kfw_controls.AUX_data_name);

            if(kfw_controls.AUX_functions_returns == -1) {
                printf("new\n");
                kfw_controls.AUX_data_st_ptr=&kfw_controls.datas_cache[kfw_controls.current_kfw_datas];


                // by setting type to 2 , we tell kernel not to check the type
                // and send us data
                kfw_controls.AUX_data_type=2;
                kfw_controls.AUX_functions_returns= talk_2_module(NULL, &kfw_controls, &kfwp_controls, 0b00000000,
                                                                  kfw_controls.AUX_data_name,
                                                                  &kfw_controls.AUX_data_type,
                                                                  NULL, kfw_controls.AUX_data_st_ptr, NULL, NULL,
                                                                  NULL);


                printf("bytes:%d\n",kfw_controls.AUX_functions_returns);
                // if we had bytes written to that address
                if(kfw_controls.AUX_functions_returns !=0)
                    kfw_controls.current_kfw_datas++;
                else
                    kfw_controls.AUX_data_st_ptr=NULL;

                printf("data#:%d\n",kfw_controls.current_kfw_datas);

            }else{
                //check consistency
                printf("show data XXX exist on cache\n");

                if(kfw_controls.datas_cache[kfw_controls.AUX_functions_returns].consistency == 1){

                        printf("show data XXX consists\n");
                        kfw_controls.AUX_data_st_ptr = &(kfw_controls.datas_cache[kfw_controls.AUX_functions_returns]);
                }
                else{
                    printf("show data XXX consistency was failed / send request to kernel\n");
                    kfw_controls.AUX_data_st_ptr=&kfw_controls.datas_cache[kfw_controls.current_kfw_datas];

                    // by setting type to 2 , we tell kernel not to check the type
                    // and send us data
                    kfw_controls.AUX_data_type=2;
                    kfw_controls.AUX_functions_returns= talk_2_module(NULL, &kfw_controls, &kfwp_controls,
                                                                      0b00000000,
                                                                      kfw_controls.AUX_data_name,
                                                                      &kfw_controls.AUX_data_type, NULL,
                                                                      kfw_controls.AUX_data_st_ptr, NULL, NULL, NULL);

                    kfw_controls.AUX_data_st_ptr->consistency=1;
                    if(kfw_controls.AUX_data_st_ptr!=NULL){ //TODO we can omit this if
                        if(kfw_controls.AUX_functions_returns==0)
                            kfw_controls.AUX_data_st_ptr->current_rules=0;
                    }

                }


            }
            if(kfw_controls.AUX_data_st_ptr!=NULL) {

                for (int i = 0; i < kfw_controls.AUX_data_st_ptr->current_rules; i++) {
                    printf("%s %s\n", kfw_controls.AUX_data_st_ptr->rules[i].type,
                           kfw_controls.AUX_data_st_ptr->rules[i].value);
                }

                printf("show data issued\n");
            }

        }

        // show policy POLICY_NAME
        else if (regexec(&kfw_regex.regex_show_policy_command, kfw_controls.user_command, 0, NULL, 0) ==0){


            split_policy_def_del_show_cmd(kfw_controls.user_command, kfw_controls.AUX_policy_name, 2, 4);

            kfw_controls.AUX_functions_returns= getindex_policy_in_policy_cache(&kfw_controls,
                                                                                kfw_controls.AUX_policy_name);



            if(kfw_controls.AUX_functions_returns == -1) {

                printf("policy not exist on cache\n");

                printf("send request\n");

                kfw_controls.AUX_policy_st_ptr=&kfw_controls.policies_cache[kfw_controls.current_kfw_policies];

                // setting arg2 for kernel means we are issuing
                // show policy POLICY_NAME command
                kfw_controls.AUX_functions_returns= talk_2_module(NULL, &kfw_controls, &kfwp_controls, 0b00000010,
                                                                  kfw_controls.AUX_policy_name, "show", NULL, NULL,
                                                                  kfw_controls.AUX_policy_st_ptr, NULL, NULL);


                printf("policy bytes:%d\n",kfw_controls.AUX_functions_returns);

                // if we had bytes written to that address
                if(kfw_controls.AUX_functions_returns !=0)
                    kfw_controls.current_kfw_policies++;
                else
                    kfw_controls.AUX_policy_st_ptr=NULL;

            }else{
                //check consistency
                printf("show policy XXX exist on cache\n");

                if(kfw_controls.policies_cache[kfw_controls.AUX_functions_returns].consistency == 1){

                    printf("show policy XXX consists\n");
                    kfw_controls.AUX_policy_st_ptr = &(kfw_controls.policies_cache[kfw_controls.AUX_functions_returns]);
                }
                else{
                    printf("show policy XXX consistency was failed / send request to kernel\n");

                    kfw_controls.AUX_policy_st_ptr=&kfw_controls.policies_cache[kfw_controls.current_kfw_policies];

                    talk_2_module(NULL, &kfw_controls, &kfwp_controls, 0b00000010, kfw_controls.AUX_policy_name,
                                  NULL,
                                  NULL, NULL, kfw_controls.AUX_policy_st_ptr, NULL, NULL);


                    kfw_controls.AUX_policy_st_ptr->consistency=1;
                    if(kfw_controls.AUX_policy_st_ptr!=NULL){ //TODO we can omit this if
                        if(kfw_controls.AUX_functions_returns==0)
                            kfw_controls.AUX_policy_st_ptr->current_data_actions=0;
                    }

                }


            }
            if(kfw_controls.AUX_policy_st_ptr!=NULL) {

                for (int i = 0; i < kfw_controls.AUX_policy_st_ptr->current_data_actions; i++) {
                    printf("%s %s\n", kfw_controls.AUX_policy_st_ptr->data_with_actions[i].data_name,
                           kfw_controls.AUX_policy_st_ptr->data_with_actions[i].action);
                }

                printf("show policy issued\n");
            }


        }

        // service policy definition
        else if (regexec(&kfw_regex.regex_service_policy_definition, kfw_controls.user_command, 0, NULL, 0) ==0) {

            //TODO Important
            // we will update the consistency flags in talk_2_module funcrion

            printf("service policy definition\n");
            split_service_policy_def_del_cmd(kfw_controls.user_command, kfw_controls.AUX_policy_name,
                                             kfw_controls.AUX_interface_name, kfw_controls.AUX_policy_direction, 1, 2,
                                             3);

            talk_2_module(&consistencyFlags, &kfw_controls, &kfwp_controls, 0b00000100, kfw_controls.AUX_policy_name,
                          kfw_controls.AUX_interface_name, kfw_controls.AUX_policy_direction, NULL, NULL, NULL, NULL);

        }

        // service policy deletion
        else if (regexec(&kfw_regex.regex_service_policy_deletion, kfw_controls.user_command, 0, NULL, 0) ==0) {

            //TODO Important
            // we will update the consistency flags in talk_2_module funcrion
            printf("service policy deletion\n");


            split_service_policy_def_del_cmd(kfw_controls.user_command, kfw_controls.AUX_policy_name,
                                             kfw_controls.AUX_interface_name, kfw_controls.AUX_policy_direction, 2, 3,
                                             4);

            talk_2_module(&consistencyFlags, &kfw_controls, &kfwp_controls, 0b10000100, kfw_controls.AUX_policy_name,
                          kfw_controls.AUX_interface_name, kfw_controls.AUX_policy_direction, NULL, NULL, NULL, NULL);

        }

        // show polices
        else if (regexec(&kfw_regex.regex_show_polices, kfw_controls.user_command, 0, NULL, 0) ==0) {

            //first check policies_cache cache consistency

            // if policies_cache was not consitent
            if(consistencyFlags.policy_cache == 0){
                // first clear datas_cache cache
                bzero(&kfw_controls.policies_cache, 10 * sizeof(policy_t)); //TODO change 10 as macro

                // send request to kernel
                kfw_controls.AUX_functions_returns= talk_2_module(&consistencyFlags, &kfw_controls, &kfwp_controls,
                                                                  0b00001111, NULL, NULL, NULL, NULL, NULL, NULL,
                                                                  NULL);

            }



            printf("policies_cache\n");
            printf("-----------------\n");
            for(int i=0;i<kfw_controls.current_kfw_policies;i++)
                printf("policy %s\n",kfw_controls.policies_cache[i].name);
        }

        // show datas_cache
        else if (regexec(&kfw_regex.regex_show_datas, kfw_controls.user_command, 0, NULL, 0) ==0) {

            //first check datas_cache cache consistency

            // if datas_cache was not consitent
            if(consistencyFlags.data_cache == 0){
                // first clear datas_cache cache
                bzero(&kfw_controls.datas_cache, 10 * sizeof(data_t)); //TODO change 10 as macro

                // send request to kernel
                kfw_controls.AUX_functions_returns= talk_2_module(&consistencyFlags, &kfw_controls, &kfwp_controls,
                                                                  0b00001110, NULL, NULL, NULL, NULL, NULL, NULL,
                                                                  NULL);

            }


            //TODO fields of output
            printf("--------DATAS-------\n");

            for(int i=0;i<kfw_controls.current_kfw_datas;i++){
                if(kfw_controls.datas_cache[i].type == 1)
                    printf("%s (all)\n",kfw_controls.datas_cache[i].name);
                else
                    printf("%s (any)\n",kfw_controls.datas_cache[i].name);

            }

        }

        // ingress  /  egress
        // show polices (in|out)
        else if (regexec(&kfw_regex.regex_show_polices_with_dir, kfw_controls.user_command, 0, NULL, 0) ==0) {


            strnsplit(kfw_controls.user_command, 2, kfw_controls.AUX_policy_direction);

            if(strcmp(kfw_controls.AUX_policy_direction,"in")==0) {

                // First check ingress policies_cache consistency
                if(consistencyFlags.ingress_policy_cache != 1){
                    printf("<<<<sent request>>>>\n");

                    // send request to kernel
                    kfw_controls.AUX_functions_returns= talk_2_module(&consistencyFlags, &kfw_controls,
                                                                      &kfwp_controls,
                                                                      0b00001000, NULL, NULL, NULL, NULL, NULL,
                                                                      &ingress_policies, NULL);
                }

                printf("ingress policies_cache\n");
                printf("-----------------\n");
                for (int i = 0; i < ingress_policies.current_ingress_policies; i++)
                    printf("%s , %s\n", ingress_policies.policyWithInterfaces[i].policy_name,
                           ingress_policies.policyWithInterfaces[i].interface_name);
            }
            else {

                // First check egress policies_cache consistency
                if(consistencyFlags.egress_policy_cache != 1){
                    printf("<<<<sent request>>>>\n");
                    // send request to kernel
                    kfw_controls.AUX_functions_returns= talk_2_module(&consistencyFlags, &kfw_controls,
                                                                      &kfwp_controls,
                                                                      0b00001001, NULL, NULL, NULL, NULL, NULL, NULL,
                                                                      &egress_policies);
                }

                printf("egress policies_cache\n");
                printf("-----------------\n");
                for(int i=0;i<egress_policies.current_egress_policies;i++)
                    printf("%s , %s\n",egress_policies.policyWithInterfaces[i].policy_name,egress_policies.policyWithInterfaces[i].interface_name);

            }
        }

        // show polices (INTERFACE)
        else if (regexec(&kfw_regex.regex_show_policies_with_int, kfw_controls.user_command, 0, NULL, 0) ==0) {

            // First check ingress policies_cache consistency
            if(consistencyFlags.ingress_policy_cache != 1){
                printf("<<<<sent request>>>>\n");
                // send request to kernel
                kfw_controls.AUX_functions_returns= talk_2_module(&consistencyFlags, &kfw_controls, &kfwp_controls,
                                                                  0b00001000, NULL, NULL, NULL, NULL, NULL,
                                                                  &ingress_policies, NULL);

            }
            else if(consistencyFlags.egress_policy_cache != 1){
                printf("<<<<sent request>>>>\n");
                // send request to kernel
                kfw_controls.AUX_functions_returns= talk_2_module(&consistencyFlags, &kfw_controls, &kfwp_controls,
                                                                  0b00001001, NULL, NULL, NULL, NULL, NULL, NULL,
                                                                  &egress_policies);
            }


            strnsplit(kfw_controls.user_command, 2, kfw_controls.AUX_interface_name);

            printf("Interface : %s\n", kfw_controls.AUX_interface_name);
            printf("Ingress\n");

            for (int i = 0; i < ingress_policies.current_ingress_policies; i++)
                if (strcmp(ingress_policies.policyWithInterfaces[i].interface_name, kfw_controls.AUX_interface_name) ==
                    0){
                    printf("   policy %s\n", ingress_policies.policyWithInterfaces[i].policy_name);
                    break;
                }
            printf("engress\n");
            for (int i = 0; i < egress_policies.current_egress_policies; i++)
                if (strcmp(egress_policies.policyWithInterfaces[i].interface_name, kfw_controls.AUX_interface_name) ==
                    0){
                    printf("   policy %s\n", egress_policies.policyWithInterfaces[i].policy_name);
                    break;
                }

        }

        // show policies_cache ( INTERFACE‌ ) (in | out)
        else if (regexec(&kfw_regex.regex_show_policies_with_int_dir, kfw_controls.user_command, 0, NULL, 0) ==0) {
            //TODO‌ make one function
            //TODO make for to a function
            strnsplit(kfw_controls.user_command, 2, kfw_controls.AUX_interface_name);
            strnsplit(kfw_controls.user_command, 3, kfw_controls.AUX_policy_direction);

            printf("Interface : %s\n", kfw_controls.AUX_interface_name);
            if(strcmp(kfw_controls.AUX_policy_direction,"in")==0) {

                // First check ingress policies_cache consistency
                if(consistencyFlags.ingress_policy_cache != 1){
                    printf("<<<<sent request>>>>\n");

                    // send request to kernel
                    kfw_controls.AUX_functions_returns= talk_2_module(&consistencyFlags, &kfw_controls,
                                                                      &kfwp_controls,
                                                                      0b00001000, NULL, NULL, NULL, NULL, NULL,
                                                                      &ingress_policies, NULL);
                }


                printf("Ingress\n");

                for (int i = 0; i < ingress_policies.current_ingress_policies; i++)
                    if (strcmp(ingress_policies.policyWithInterfaces[i].interface_name,
                               kfw_controls.AUX_interface_name) ==
                        0) {
                        printf("   policy %s\n", ingress_policies.policyWithInterfaces[i].policy_name);
                        break;
                    }
            }
            else {

                // First check egress policies_cache consistency
                if(consistencyFlags.egress_policy_cache != 1){
                    printf("<<<<sent request>>>>\n");
                    // send request to kernel
                    kfw_controls.AUX_functions_returns= talk_2_module(&consistencyFlags, &kfw_controls,
                                                                      &kfwp_controls,
                                                                      0b00001001, NULL, NULL, NULL, NULL, NULL, NULL,
                                                                      &egress_policies);
                }

                printf("engress\n");
                for (int i = 0; i < egress_policies.current_egress_policies; i++)
                    if (strcmp(egress_policies.policyWithInterfaces[i].interface_name,
                               kfw_controls.AUX_interface_name) ==
                        0) {
                        printf("   policy %s\n", egress_policies.policyWithInterfaces[i].policy_name);
                        break;
                    }
            }
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
