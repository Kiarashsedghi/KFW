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
#include <unistd.h>


#include "../header_files/kfw_user.h"
#include "../header_files/kfw_user_functions.h"


#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wpointer-sign"



int main() {

    //------------------------INITIALIZATION---------------------------------

    // defining ingress_policies and egress_policies
    ingress_policies_t ingress_policies;
    egress_policies_t egress_policies;

    // initialize current policies in both ingress and egress to 0
    ingress_policies.current_ingress_policies=0;
    egress_policies.current_egress_policies=0;


    // creating consistency flags struct
    consistency_flags_t consistencyFlags;

    // initializing all flags to 0(inconsistent)
    consistencyFlags.data_cache=0;
    consistencyFlags.policy_cache=0;
    consistencyFlags.ingress_policy_cache=0;
    consistencyFlags.egress_policy_cache=0;



    // create kfw_controls to control kfw program.
    kfw_controls_t kfw_controls;

    // initialize current datas and policies in cache to 0
    kfw_controls.current_kfw_datas=0;
    kfw_controls.current_kfw_policies=0;

    // initialize user command with \0(clearing)
    bzero(&(kfw_controls.user_command),MAX_LEN_USER_COMMAND);

    // initialize kfw_controls.AUX_data_name with \0(clearing)
    bzero(kfw_controls.AUX_data_name,MAX_LEN_DATA_NAME);

    // initialize kfw_controls.AUX_policy_name with \0(clearing)
    bzero(kfw_controls.AUX_policy_name,MAX_LEN_POLICY_NAME);

    // initialize kfw_controls.AUX_policy_direction with \0(clearing)
    bzero(kfw_controls.AUX_policy_direction,MAX_LEN_POLICY_DIRECTION);

    // initialize kfw_controls.AUX_interface_name with \0(clearing)
    bzero(kfw_controls.AUX_interface_name,MAX_LEN_INTERFACE_NAME);

    // initialize kfw_controls.AUX_rule_type with \0(clearing)
    bzero(kfw_controls.AUX_rule_type,MAX_LEN_RULE_TYPE);

    // initialize kfw_controls.AUX_rule_type with \0(clearing)
    bzero(kfw_controls.AUX_rule_type,MAX_LEN_RULE_VALUE);


    // create kfw_regex to handle program commands regex
    regex__t kfw_regex;

    // compiling regexes defined for kfw
    compile_kfw_cmds_regexes(&kfw_regex);

    // create kfwp_controls to control connection between user space program and kernel module.
    kfwp_controls_t kfwp_controls;


    //-----------------------------------------------------------------------



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
                printd("data was not found on cache , sending request\n");

                kfw_controls.AUX_data_st_ptr=&kfw_controls.datas_cache[kfw_controls.current_kfw_datas];

                kfw_controls.AUX_functions_returns= talk2module(NULL, &kfw_controls, &kfwp_controls, 0b00000000,
                                                                kfw_controls.AUX_data_name,
                                                                &kfw_controls.AUX_data_type,
                                                                NULL, kfw_controls.AUX_data_st_ptr, NULL, NULL,
                                                                NULL);

                // if we had bytes written to the cache
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
                printf("data was found on cache\n");

                if(kfw_controls.datas_cache[kfw_controls.AUX_functions_returns].consistency == 1){
                    /* We should check whether data_type specified* by user_command matches
                     * data_type of the data we have found.
                     *
                     * Users Cannot change the type whenever they enter data definition mode.
                    */
                    if(kfw_controls.datas_cache[kfw_controls.AUX_functions_returns].type != kfw_controls.AUX_data_type){
                        printe("Cannot change type for data %s\nTo change the type first delete the type and recreate it"); //TODO‌ name
                        continue;
                    }
                    else
                        kfw_controls.AUX_data_st_ptr = &(kfw_controls.datas_cache[kfw_controls.AUX_functions_returns]);
                }
                else{
                    printf("data was found on cache but was not consistent / sending request\n");
                    kfw_controls.AUX_data_st_ptr=&kfw_controls.datas_cache[kfw_controls.current_kfw_datas];

                    kfw_controls.AUX_functions_returns= talk2module(NULL, &kfw_controls, &kfwp_controls,
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

                    // send request for the rule
                    talk2module(NULL, &kfw_controls, &kfwp_controls, 0b00000001, kfw_controls.AUX_rule_type,
                                kfw_controls.AUX_rule_value, kfw_controls.AUX_data_name,
                                &kfw_controls.datas_cache[kfw_controls.AUX_functions_returns], NULL, NULL, NULL);



                    //set consistency flag to 0
                    if(kfw_controls.AUX_data_st_ptr!=NULL) {
                        kfw_controls.AUX_data_st_ptr->consistency = 0;
                        printf("data is now inconsistent\n");//TODO name
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
                    talk2module(NULL, &kfw_controls, &kfwp_controls, 0b10000001, kfw_controls.AUX_rule_type,
                                kfw_controls.AUX_rule_value, kfw_controls.AUX_data_name,
                                &kfw_controls.datas_cache[kfw_controls.AUX_functions_returns], NULL, NULL, NULL);

                    // set consistency flag to 0
                    if(kfw_controls.AUX_data_st_ptr!=NULL) {
                        kfw_controls.AUX_data_st_ptr->consistency = 0;
                        printf("data is now inconsistent\n");//TODO‌ name
                    }
                    // set datas_cache array consistancy to 0
                    consistencyFlags.data_cache=0;

                }

                    // quick clear
                else if (regexec(&kfw_regex.regex_quick_clear, kfw_controls.user_command, 0, NULL, 0) == 0) {
                    talk2module(NULL, &kfw_controls, &kfwp_controls, 0b01111110, "NULL", "NULL", "NULL", NULL,
                                NULL,
                                NULL, NULL);

                    //set consistency flag to 0
                    if(kfw_controls.AUX_data_st_ptr!=NULL) {
                        kfw_controls.AUX_data_st_ptr->consistency = 0;
                        printf("data is now inconsistent\n");//TODO name
                    }
                    // set datas_cache array consistancy to 0
                    consistencyFlags.data_cache=0;

                }

                    // quick  show
                else if (regexec(&kfw_regex.regex_quick_show, kfw_controls.user_command, 0, NULL, 0) == 0) {


                    if(kfw_controls.AUX_data_st_ptr!=NULL){
                        printd("data was found on the cache\n");
                        if(kfw_controls.AUX_data_st_ptr->consistency==1){
                        printd("reading from cache data was consistent\n");
                        printf("rules\n");
                        printf("--------------\n");
                        for (int i = 0; i < kfw_controls.AUX_data_st_ptr->current_rules; i++) {
                            printf("%s %s\n", kfw_controls.AUX_data_st_ptr->rules[i].type, kfw_controls.AUX_data_st_ptr->rules[i].value);
                            }
                        }
                        else{
                            printf("data was not consistent , sending request\n");

                            // send request to kernel
                            kfw_controls.AUX_functions_returns= talk2module(NULL, &kfw_controls, &kfwp_controls,
                                                                            0b00000000,
                                                                            kfw_controls.AUX_data_name,
                                                                            &kfw_controls.AUX_data_type, NULL,
                                                                            kfw_controls.AUX_data_st_ptr, NULL, NULL,
                                                                            NULL);

                            kfw_controls.AUX_data_st_ptr->consistency=1;

                                // update cache if does not consistent with kernel
                            if(kfw_controls.AUX_functions_returns==0)
                                kfw_controls.AUX_data_st_ptr->current_rules=0;
                            else {
                                printf("rules\n");
                                printf("--------------\n");
                                for (int i = 0; i < kfw_controls.AUX_data_st_ptr->current_rules; i++) {
                                    printf("%s %s\n", kfw_controls.AUX_data_st_ptr->rules[i].type,
                                           kfw_controls.AUX_data_st_ptr->rules[i].value);
                                }
                            }
                    }

                }
                    else{
                        printd("data was not found on the cache , sending request\n");
                        // send request to kernel
                        kfw_controls.AUX_functions_returns= talk2module(NULL, &kfw_controls, &kfwp_controls,
                                                                        0b00000000,
                                                                        kfw_controls.AUX_data_name,
                                                                        &kfw_controls.AUX_data_type, NULL,
                                                                        kfw_controls.AUX_data_st_ptr, NULL, NULL,
                                                                        NULL);


                        // update cache if exist and if does not consistent with kernel
                        if(kfw_controls.AUX_data_st_ptr!=NULL){
                            kfw_controls.AUX_data_st_ptr->consistency=1;


                            if(kfw_controls.AUX_functions_returns==0)
                                kfw_controls.AUX_data_st_ptr->current_rules=0;
                            else {
                                printf("rules\n");
                                printf("--------------\n");
                                for (int i = 0; i < kfw_controls.AUX_data_st_ptr->current_rules; i++) {
                                    printf("%s %s\n", kfw_controls.AUX_data_st_ptr->rules[i].type,
                                           kfw_controls.AUX_data_st_ptr->rules[i].value);
                                }
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
                printf("policy was not found on cache , sending request\n");
                kfw_controls.AUX_policy_st_ptr=&kfw_controls.policies_cache[kfw_controls.current_kfw_policies];

                kfw_controls.AUX_functions_returns= talk2module(NULL, &kfw_controls, &kfwp_controls, 0b00000010,
                                                                kfw_controls.AUX_policy_name, NULL, NULL, NULL,
                                                                kfw_controls.AUX_policy_st_ptr, NULL, NULL);


                // if we had bytes written to that address
                if(kfw_controls.AUX_functions_returns !=0)
                    kfw_controls.current_kfw_policies++;
                else
                    kfw_controls.AUX_policy_st_ptr=NULL;

                // set policies_cache array consistancy to 0 because the policy probabaly
                // created/entered with no data
                consistencyFlags.policy_cache=0; //TODO

            }
            else {
                printd("policy was found on cache\n");

                if(kfw_controls.policies_cache[kfw_controls.AUX_functions_returns].consistency == 1){
                    printd("policy was consistent\n");

                        kfw_controls.AUX_policy_st_ptr = &(kfw_controls.policies_cache[kfw_controls.AUX_functions_returns]);
                }
                else{
                    printd("consistency was failed / sending request\n");

                    kfw_controls.AUX_policy_st_ptr=&kfw_controls.policies_cache[kfw_controls.current_kfw_policies];

                    talk2module(NULL, &kfw_controls, &kfwp_controls, 0b00000010, kfw_controls.AUX_policy_name,
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

                    bzero(kfw_controls.AUX_data_name,strlen(kfw_controls.AUX_data_name));
                    bzero(kfw_controls.AUX_action_name,strlen(kfw_controls.AUX_action_name));

                    split_data_action_def_del_cmd(kfw_controls.user_command, kfw_controls.AUX_data_name,
                                                  kfw_controls.AUX_action_name, 0, 1);


                    talk2module(NULL, &kfw_controls, &kfwp_controls, 0b00000011, kfw_controls.AUX_data_name,
                                kfw_controls.AUX_action_name, NULL,
                                NULL, &kfw_controls.policies_cache[kfw_controls.AUX_functions_returns], NULL, NULL);




                    //set consistency flag to 0
                    if(kfw_controls.AUX_policy_st_ptr!=NULL) {
                        kfw_controls.AUX_policy_st_ptr->consistency = 0;
                        printf("policy is now inconsistent\n");
                    }

                    // set policies_cache array consistency to 0 because the policy probably
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


                    talk2module(NULL, &kfw_controls, &kfwp_controls, 0b10000011, kfw_controls.AUX_data_name,
                                kfw_controls.AUX_action_name, NULL,
                                NULL, &kfw_controls.policies_cache[kfw_controls.AUX_functions_returns], NULL, NULL);

                    //set consistency flag to 0
                    if(kfw_controls.AUX_policy_st_ptr!=NULL) {
                        kfw_controls.AUX_policy_st_ptr->consistency = 0;
                        printf("policy is now inconsistent\n");
                    }
                    // set policies_cache array consistancy to 0 because the policy probabaly
                    // changed
                    consistencyFlags.policy_cache=0; //TODO


                }

                // quick show
                else if (regexec(&kfw_regex.regex_quick_show, kfw_controls.user_command, 0, NULL, 0) ==0) {


                    if(kfw_controls.AUX_policy_st_ptr!=NULL){
                        printd("policy was found on the cache\n");
                        if(kfw_controls.AUX_policy_st_ptr->consistency==1){
                            printd("reading from cache policy was consistent\n");
                            printf("data action\n");
                            printf("--------------\n");
                            for(int i = 0; i < kfw_controls.AUX_policy_st_ptr->current_data_actions; i++) {
                                printf("%s %s\n", kfw_controls.AUX_policy_st_ptr->data_with_actions[i].data_name, kfw_controls.AUX_policy_st_ptr->data_with_actions[i].action);
                            }
                        }
                        else{
                            printd("policy was not consistent , sending request\n");
                            // send request to kernel
                            kfw_controls.AUX_functions_returns= talk2module(NULL, &kfw_controls, &kfwp_controls,
                                                                            0b00000010, kfw_controls.AUX_policy_name,
                                                                            NULL, NULL,
                                                                            NULL,
                                                                            kfw_controls.AUX_policy_st_ptr, NULL,
                                                                            NULL);

                            kfw_controls.AUX_policy_st_ptr->consistency=1;

                            // update cache if does not consistent with kernel
                            if(kfw_controls.AUX_functions_returns==0)
                                kfw_controls.AUX_policy_st_ptr->current_data_actions=0;
                            else {
                                printf("data action\n");
                                printf("--------------\n");
                                for (int i = 0; i < kfw_controls.AUX_policy_st_ptr->current_data_actions; i++) {
                                    printf("%s %s\n", kfw_controls.AUX_policy_st_ptr->data_with_actions[i].data_name,
                                           kfw_controls.AUX_policy_st_ptr->data_with_actions[i].action);
                                }
                            }
                        }

                    }else{
                        printd("policy was not found on the cache , sending request\n");
                        // send request to kernel
                        kfw_controls.AUX_functions_returns= talk2module(NULL, &kfw_controls, &kfwp_controls,
                                                                        0b00000010,
                                                                        kfw_controls.AUX_policy_name,
                                                                        NULL, NULL, NULL,
                                                                        kfw_controls.AUX_policy_st_ptr, NULL, NULL);

                        // update cache if exist and if does not consistent with kernel
                        if(kfw_controls.AUX_policy_st_ptr!=NULL){

                            kfw_controls.AUX_policy_st_ptr->consistency=1;

                            if(kfw_controls.AUX_functions_returns==0)
                                kfw_controls.AUX_policy_st_ptr-> current_data_actions=0;
                            else {
                                printf("data action\n");
                                printf("--------------\n");
                                for (int i = 0; i < kfw_controls.AUX_policy_st_ptr->current_data_actions; i++) {
                                    printf("%s %s\n", kfw_controls.AUX_policy_st_ptr->data_with_actions[i].data_name,
                                           kfw_controls.AUX_policy_st_ptr->data_with_actions[i].action);
                                }
                            }
                        }
                    }

                }

                    // quick clear
                else if (regexec(&kfw_regex.regex_quick_clear, kfw_controls.user_command, 0, NULL, 0) ==0) {

                    talk2module(NULL, &kfw_controls, &kfwp_controls, 0b01111111, NULL, NULL, NULL, NULL,
                                NULL,
                                NULL, NULL);

                    //set consistency flag to 0
                    if(kfw_controls.AUX_policy_st_ptr!=NULL) {
                        kfw_controls.AUX_policy_st_ptr->consistency = 0;
                        printd("policy is now inconsistent\n");//TODO name
                    }
                    // set policies_cache array consistency to 0 because the policy probably
                    // changed
                    consistencyFlags.policy_cache=0;

                }
            }
        }


        // data deletion
        else if(regexec(&kfw_regex.regex_data_deletion, kfw_controls.user_command, 0, NULL, 0) ==0) {
            /*
             * Data deletion command acceptance:
             *          no data DATA_NAME (all/any)?   * specifying (any/all) is optional and does not effect deletion
             *
             * */


            split_data_def_del_cmd(kfw_controls.user_command, kfw_controls.AUX_data_name, &kfw_controls.AUX_data_type,
                                   2, 2);

            // send deletion request to kernel
            kfw_controls.AUX_functions_returns= talk2module(NULL, &kfw_controls, &kfwp_controls, 0b10000000,
                                                            kfw_controls.AUX_data_name,
                                                            &kfw_controls.AUX_data_type,
                                                            NULL, NULL, NULL, NULL, NULL);


            // deleting the data from the cache

            // when we delete the data from cache we do not change datas_cache array consistency flag
            // that is because we are also deleting it from the cache

            // if the data was deleted in kernel
            if(kfw_controls.AUX_functions_returns==0)
                data_del_cache(&kfw_controls);

        }

        // policy deletion
        else if(regexec(&kfw_regex.regex_policy_deletion, kfw_controls.user_command, 0, NULL, 0) ==0) {

            bzero(kfw_controls.AUX_policy_name,strlen(kfw_controls.AUX_policy_name));
            split_policy_def_del_show_cmd(kfw_controls.user_command, kfw_controls.AUX_policy_name, 2, 2);


            kfw_controls.AUX_functions_returns= talk2module(NULL, &kfw_controls, &kfwp_controls, 0b10000010,
                                                            kfw_controls.AUX_policy_name, NULL, NULL, NULL, NULL,
                                                            NULL,
                                                            NULL);

            // if the policy was deleted in kernel
            if(kfw_controls.AUX_functions_returns==0)
                policy_del_cache(&kfw_controls);

        }

        // show data DATA_NAME
        else if (regexec(&kfw_regex.regex_show_data_command, kfw_controls.user_command, 0, NULL, 0) ==0){

            split_data_def_del_cmd(kfw_controls.user_command, kfw_controls.AUX_data_name, &kfw_controls.AUX_data_type,
                                   2, 4);

            kfw_controls.AUX_functions_returns= getindex_data_in_data_cache(&kfw_controls, kfw_controls.AUX_data_name);

            if(kfw_controls.AUX_functions_returns == -1) {
                printd("Data requested was not found on cache , sending request\n");
                kfw_controls.AUX_data_st_ptr=&kfw_controls.datas_cache[kfw_controls.current_kfw_datas];


                // by setting type to 2 , we tell kernel not to check the type
                // and send us data
                kfw_controls.AUX_data_type=2;
                kfw_controls.AUX_functions_returns= talk2module(NULL, &kfw_controls, &kfwp_controls, 0b00000000,
                                                                kfw_controls.AUX_data_name,
                                                                &kfw_controls.AUX_data_type,
                                                                NULL, kfw_controls.AUX_data_st_ptr, NULL, NULL,
                                                                NULL);

                // if we had bytes written to that address
                if(kfw_controls.AUX_functions_returns !=0)
                    kfw_controls.current_kfw_datas++;
                else
                    kfw_controls.AUX_data_st_ptr=NULL;


            }else{
                //check consistency
                printd("data was found on cache\n");

                if(kfw_controls.datas_cache[kfw_controls.AUX_functions_returns].consistency == 1){

                    printd("data was consistent\n");
                        kfw_controls.AUX_data_st_ptr = &(kfw_controls.datas_cache[kfw_controls.AUX_functions_returns]);
                }
                else{
                    printd("data consistency was failed , sending request\n");
                    kfw_controls.AUX_data_st_ptr=&kfw_controls.datas_cache[kfw_controls.current_kfw_datas];

                    // by setting type to 2 , we tell kernel not to check the type
                    // and send us data
                    kfw_controls.AUX_data_type=2;
                    kfw_controls.AUX_functions_returns= talk2module(NULL, &kfw_controls, &kfwp_controls,
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
                printf("rules\n");
                printf("--------------\n");
                for (int i = 0; i < kfw_controls.AUX_data_st_ptr->current_rules; i++) {
                    printf("%s %s\n", kfw_controls.AUX_data_st_ptr->rules[i].type,
                           kfw_controls.AUX_data_st_ptr->rules[i].value);
                }
            }

        }

        // show policy POLICY_NAME
        else if (regexec(&kfw_regex.regex_show_policy_command, kfw_controls.user_command, 0, NULL, 0) ==0){

            split_policy_def_del_show_cmd(kfw_controls.user_command, kfw_controls.AUX_policy_name, 2, 4);

            kfw_controls.AUX_functions_returns= getindex_policy_in_policy_cache(&kfw_controls,
                                                                                kfw_controls.AUX_policy_name);



            if(kfw_controls.AUX_functions_returns == -1) {

                printd("policy was not found on cache , sending request\n");

                kfw_controls.AUX_policy_st_ptr=&kfw_controls.policies_cache[kfw_controls.current_kfw_policies];

                // setting arg2 for kernel means we are issuing
                // show policy POLICY_NAME command
                kfw_controls.AUX_functions_returns= talk2module(NULL, &kfw_controls, &kfwp_controls, 0b00000010,
                                                                kfw_controls.AUX_policy_name, "show", NULL, NULL,
                                                                kfw_controls.AUX_policy_st_ptr, NULL, NULL);


                // if we had bytes written to that address
                if(kfw_controls.AUX_functions_returns !=0)
                    kfw_controls.current_kfw_policies++;
                else
                    kfw_controls.AUX_policy_st_ptr=NULL;

            }else{
                //check consistency
                printd("policy was found on cache\n"); //TODO‌ name

                if(kfw_controls.policies_cache[kfw_controls.AUX_functions_returns].consistency == 1){

                    printd("policy was consistent\n");
                    kfw_controls.AUX_policy_st_ptr = &(kfw_controls.policies_cache[kfw_controls.AUX_functions_returns]);
                }
                else{
                    printd("policy consistency was failed / send request to kernel\n");

                    kfw_controls.AUX_policy_st_ptr=&kfw_controls.policies_cache[kfw_controls.current_kfw_policies];

                    talk2module(NULL, &kfw_controls, &kfwp_controls, 0b00000010, kfw_controls.AUX_policy_name,
                                NULL,
                                NULL, NULL, kfw_controls.AUX_policy_st_ptr, NULL, NULL);


                    kfw_controls.AUX_policy_st_ptr->consistency=1;
                    if(kfw_controls.AUX_policy_st_ptr!=NULL){ //TODO we can omit this if
                        if(kfw_controls.AUX_functions_returns==0)
                            kfw_controls.AUX_policy_st_ptr->current_data_actions=0;
                    }

                }


            }
            printf("data action\n");
            printf("--------------\n");
            if(kfw_controls.AUX_policy_st_ptr!=NULL) {
                for (int i = 0; i < kfw_controls.AUX_policy_st_ptr->current_data_actions; i++) {
                    printf("%s %s\n", kfw_controls.AUX_policy_st_ptr->data_with_actions[i].data_name,
                           kfw_controls.AUX_policy_st_ptr->data_with_actions[i].action);
                }
            }

        }


        // service policy definition
        else if (regexec(&kfw_regex.regex_service_policy_definition, kfw_controls.user_command, 0, NULL, 0) ==0) {

            // consistency flag is updated in talk2module function

            split_service_policy_def_del_cmd(kfw_controls.user_command, kfw_controls.AUX_policy_name,
                                             kfw_controls.AUX_interface_name, kfw_controls.AUX_policy_direction, 1, 2,
                                             3);

            talk2module(&consistencyFlags, &kfw_controls, &kfwp_controls, 0b00000100, kfw_controls.AUX_policy_name,
                        kfw_controls.AUX_interface_name, kfw_controls.AUX_policy_direction, NULL, NULL, NULL, NULL);

        }

        // service policy deletion
        else if (regexec(&kfw_regex.regex_service_policy_deletion, kfw_controls.user_command, 0, NULL, 0) ==0) {

            // consistency flag is updated in talk2module function

            split_service_policy_def_del_cmd(kfw_controls.user_command, kfw_controls.AUX_policy_name,
                                             kfw_controls.AUX_interface_name, kfw_controls.AUX_policy_direction, 2, 3,
                                             4);

            talk2module(&consistencyFlags, &kfw_controls, &kfwp_controls, 0b10000100, kfw_controls.AUX_policy_name,
                        kfw_controls.AUX_interface_name, kfw_controls.AUX_policy_direction, NULL, NULL, NULL, NULL);

        }

        // show polices
        else if (regexec(&kfw_regex.regex_show_polices, kfw_controls.user_command, 0, NULL, 0) ==0) {

            //first check policies_cache consistency

            // if policies_cache was not consistent
            if(consistencyFlags.policy_cache == 0){
                printd("policies cache was not consistent , sending request\n");

                // first clear policies_cache
                bzero(&kfw_controls.policies_cache, MAX_POLICY_IN_KFW * sizeof(policy_t));

                // send request to kernel
                kfw_controls.AUX_functions_returns= talk2module(&consistencyFlags, &kfw_controls, &kfwp_controls,
                                                                0b00001111, NULL, NULL, NULL, NULL, NULL, NULL,
                                                                NULL);

            }

            printf("policies_cache\n");
            printf("-----------------\n");
            for(int i=0;i<kfw_controls.current_kfw_policies;i++)
                printf("policy %s\n",kfw_controls.policies_cache[i].name);
        }

        // show datas
        else if (regexec(&kfw_regex.regex_show_datas, kfw_controls.user_command, 0, NULL, 0) ==0) {

            //first check datas_cache cache consistency

            // if datas_cache was not consitent
            if(consistencyFlags.data_cache == 0){
                // first clear datas_cache cache
                bzero(&kfw_controls.datas_cache, MAX_DATA_IN_KFW * sizeof(data_t));

                // send request to kernel
                kfw_controls.AUX_functions_returns= talk2module(&consistencyFlags, &kfw_controls, &kfwp_controls,
                                                                0b00001110, NULL, NULL, NULL, NULL, NULL, NULL,
                                                                NULL);
            }


            //TODO fields of output
            printf("--------DATAS-------\n");
            printf("Name  Type  #Rule\n");

            for(int i=0;i<kfw_controls.current_kfw_datas;i++){
                if(kfw_controls.datas_cache[i].type == 1)
                    printf("%s (all) %d\n",kfw_controls.datas_cache[i].name,kfw_controls.datas_cache[i].current_rules);
                else
                    printf("%s (any) %d\n",kfw_controls.datas_cache[i].name,kfw_controls.datas_cache[i].current_rules);
            }

        }


        // ingress  /  egress
        // show polices (in|out)
        else if (regexec(&kfw_regex.regex_show_polices_with_dir, kfw_controls.user_command, 0, NULL, 0) ==0) {


            strnsplit(kfw_controls.user_command, 2, kfw_controls.AUX_policy_direction);

            if(strcmp(kfw_controls.AUX_policy_direction,"in")==0) {

                // First check ingress policies_cache consistency
                if(consistencyFlags.ingress_policy_cache != 1){
                    printd("ingress policies cache was not consistent , sending request \n");

                    // send request to kernel
                    kfw_controls.AUX_functions_returns= talk2module(&consistencyFlags, &kfw_controls,
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
                    printd("egress policies cache was not consistent , sending request \n");

                    // send request to kernel
                    kfw_controls.AUX_functions_returns= talk2module(&consistencyFlags, &kfw_controls,
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
                printd("ingress policies cache was not consistent , sending request \n");
                // send request to kernel
                kfw_controls.AUX_functions_returns= talk2module(&consistencyFlags, &kfw_controls, &kfwp_controls,
                                                                0b00001000, NULL, NULL, NULL, NULL, NULL,
                                                                &ingress_policies, NULL);

            }
            else if(consistencyFlags.egress_policy_cache != 1){
                printd("egress policies cache was not consistent , sending request \n");
                // send request to kernel
                kfw_controls.AUX_functions_returns= talk2module(&consistencyFlags, &kfw_controls, &kfwp_controls,
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

            strnsplit(kfw_controls.user_command, 2, kfw_controls.AUX_interface_name);
            strnsplit(kfw_controls.user_command, 3, kfw_controls.AUX_policy_direction);

            printf("Interface : %s\n", kfw_controls.AUX_interface_name);
            if(strcmp(kfw_controls.AUX_policy_direction,"in")==0) {

                // First check ingress policies_cache consistency
                if(consistencyFlags.ingress_policy_cache != 1){
                    printd("ingress policies cache was not consistent , sending request \n");

                    // send request to kernel
                    kfw_controls.AUX_functions_returns= talk2module(&consistencyFlags, &kfw_controls,
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
                    printd("egress policies cache was not consistent , sending request \n");
                    // send request to kernel
                    kfw_controls.AUX_functions_returns= talk2module(&consistencyFlags, &kfw_controls,
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


}
