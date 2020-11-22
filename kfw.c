#include <stdio.h>
#include "string.h"
#include "regex.h"
#include "kfw.h"
#include <unistd.h>
#include <stdlib.h>
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wpointer-sign"



twobyte_p_t  send_to_kernel(consistency_flags_t *consistencyFlags,kfw_controls_t *kfw_controls,kfwp_controls_t *kfwp_controls ,onebyte_p_t type,onebyte_p_t*arg1,onebyte_p_t  *arg2,
        onebyte_p_t *context,data_t *data_ptr , policy_t * policy_ptr){

    kfwp_controls->nlh=NULL;


    kfwp_controls->sock_fd=socket(PF_NETLINK, SOCK_RAW, NETLINK_USER);

    if(kfwp_controls->sock_fd<0)
        return -1;

    memset(&kfwp_controls->src_addr, 0, sizeof(kfwp_controls->src_addr));
    kfwp_controls->src_addr.nl_family = AF_NETLINK;
    kfwp_controls->src_addr.nl_pid = getpid(); /* self pid */

    bind(kfwp_controls->sock_fd, (struct sockaddr*)&kfwp_controls->src_addr, sizeof(kfwp_controls->src_addr));

    memset(&kfwp_controls->dest_addr, 0, sizeof(kfwp_controls->dest_addr));
    kfwp_controls->dest_addr.nl_family = AF_NETLINK;
    kfwp_controls->dest_addr.nl_pid = 0; /* For Linux Kernel */
    kfwp_controls->dest_addr.nl_groups = 0; /* unicast */


    kfwp_controls->nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(1024));
    memset(kfwp_controls->nlh, 0, NLMSG_SPACE(1024));
    kfwp_controls->nlh->nlmsg_len = NLMSG_SPACE(1024);
    kfwp_controls->nlh->nlmsg_pid = getpid();
    kfwp_controls->nlh->nlmsg_flags = 0;



    kfwp_controls->iov.iov_base = (void *)kfwp_controls->nlh;
    kfwp_controls->iov.iov_len = kfwp_controls->nlh->nlmsg_len;
    kfwp_controls->msg.msg_name = (void *)&kfwp_controls->dest_addr;
    kfwp_controls->msg.msg_namelen = sizeof(kfwp_controls->dest_addr);
    kfwp_controls->msg.msg_iov = &kfwp_controls->iov;
    kfwp_controls->msg.msg_iovlen = 1;






    kfwp_controls->kfwp_msg=(kfwp_req_t *)malloc(60);

    bzero(kfwp_controls->kfwp_msg,sizeof(kfwp_req_t));
    kfwp_controls->kfwp_msg->type=type;

    // arg1 should not be copied for (show datas , show policies) commands
    // in those commands , arg1 is NULL
    if(arg1!=NULL)
        strcpy(kfwp_controls->kfwp_msg->arg1,arg1);

    // This checking is for policies that does not have arg2 like policy definition
    if(arg2!=NULL) {
        if (type == 0b00000000)
            memcpy(kfwp_controls->kfwp_msg->arg2, arg2, 1);
        else
            memcpy(kfwp_controls->kfwp_msg->arg2, arg2, strlen(arg2));
    }
    if (context != NULL)
        memcpy(kfwp_controls->kfwp_msg->context, context, strlen(context));

    printf("ctx:%s\n",kfwp_controls->kfwp_msg->context);


    memcpy(NLMSG_DATA(kfwp_controls->nlh), kfwp_controls->kfwp_msg, sizeof(kfwp_req_t));

    printf("Sent1%s\n",kfwp_controls->kfwp_msg->arg1);
    printf("Sent2\n");

    printf("Sent3\n");

    sendmsg(kfwp_controls->sock_fd, &kfwp_controls->msg, 0);

    printf("Sent\n");
    free(kfwp_controls->kfwp_msg);
    printf("inja bade sent\n");


    kfwp_controls->kfwprep_msg=(kfwp_reply_t *)malloc(4);


    recvmsg(kfwp_controls->sock_fd, &kfwp_controls->msg, 0);
    printf("inja bade sent3\n");

    // read first 3 bytes
    memcpy(kfwp_controls->kfwprep_msg,NLMSG_DATA(kfwp_controls->nlh),4);
    // read rest of the bytes
//    memcpy(kfwp_controls->kfwprep_msg + 3, NLMSG_DATA(kfwp_controls->nlh) ,kfwp_controls->kfwprep_msg->payload_size);



    if((kfwp_controls->kfwprep_msg->status)==0b00000000) {
        if (type == 0b00000000) {
            if (kfwp_controls->kfwprep_msg->dg_cnt != 0) {
                printf("sth%d\n", kfwp_controls->kfwprep_msg->dg_cnt);
                printf("sth%d\n", kfwp_controls->kfwprep_msg->dg_size);



                if (data_ptr == NULL) {

                    kfw_controls->AUX_data_st_ptr = &kfw_controls->datas[kfw_controls->current_kfw_datas];
                    data_ptr=kfw_controls->AUX_data_st_ptr;
                    kfw_controls->current_kfw_datas++;
                    printf("new data allocated on cache\n");
                }


                for(int i=0;i<kfwp_controls->kfwprep_msg->dg_cnt;i++) {
                    recvmsg(kfwp_controls->sock_fd, &kfwp_controls->msg, 0);
                    if (i == kfwp_controls->kfwprep_msg->dg_cnt - 1) {
                        memcpy((void *) data_ptr + i * kfwp_controls->kfwprep_msg->dg_size,
                               NLMSG_DATA(kfwp_controls->nlh),
                               sizeof(data_t) - i * kfwp_controls->kfwprep_msg->dg_size+1);


                    }else
                        memcpy((void *) data_ptr + i * kfwp_controls->kfwprep_msg->dg_size,
                               NLMSG_DATA(kfwp_controls->nlh), kfwp_controls->kfwprep_msg->dg_size);

                }

                // set consistency flag to 1
                data_ptr->consistency=1;




                close(kfwp_controls->sock_fd);

                // return number of bytes written to the destination
                return  sizeof(data_t);

            } else
                printf("success creation of data no data\n");
        }

        else if(type == 0b10000000)
            printf("data deleted successfully!\n");

        else if(type == 0b10000010)
            printf("policy deleted successfully!\n");

        else if(type==0b00001110){
            printf("sth%d\n", kfwp_controls->kfwprep_msg->dg_cnt);
            printf("sth%d\n", kfwp_controls->kfwprep_msg->dg_size);


            for(int i=0;i<kfwp_controls->kfwprep_msg->dg_cnt;i++){
                recvmsg(kfwp_controls->sock_fd, &kfwp_controls->msg, 0);


                memcpy((void *)&kfw_controls->datas+i*sizeof(data_t) , NLMSG_DATA(kfwp_controls->nlh) ,kfwp_controls->kfwprep_msg->dg_size);

                // make each datas consistency to 0
                kfw_controls->datas[i].consistency=0;
                printf("%d",i);
            }
            printf("data 1 %s %d\n",kfw_controls->datas[0].name,kfw_controls->datas[0].current_rules);
            printf("data 2 %s %d\n",kfw_controls->datas[1].name,kfw_controls->datas[1].current_rules);

            printf("writing headers completed\n");

            //update number of current datas
            kfw_controls->current_kfw_datas=kfwp_controls->kfwprep_msg->dg_cnt;

            // set datas consistancy flag to 1
            // later show datas does not need request
            consistencyFlags->datas=1;


        }


        else if(type==0b00001111){

            printf("sth%d\n", kfwp_controls->kfwprep_msg->dg_cnt);
            printf("sth%d\n", kfwp_controls->kfwprep_msg->dg_size);


            for(int i=0;i<kfwp_controls->kfwprep_msg->dg_cnt;i++){
                recvmsg(kfwp_controls->sock_fd, &kfwp_controls->msg, 0);


                memcpy((void *)&kfw_controls->policies+i*sizeof(policy_t) , NLMSG_DATA(kfwp_controls->nlh) ,kfwp_controls->kfwprep_msg->dg_size);

                // make each datas consistency to 0
                kfw_controls->policies[i].consistency=0;
                printf("%d",i);
            }
            printf("writing headers completed\n");

            //update number of current datas
            kfw_controls->current_kfw_policies=kfwp_controls->kfwprep_msg->dg_cnt;

            printf(">>>>>%s",kfw_controls->policies[0].name);
            // set policies consistancy flag to 1
            // later show datas does not need request
            consistencyFlags->policies=1;

        }


        else if (type == 0b00000010){

            if (kfwp_controls->kfwprep_msg->dg_cnt != 0) {
                printf("policy :sth%d\n", kfwp_controls->kfwprep_msg->dg_cnt);
                printf("policy :sth%d\n", kfwp_controls->kfwprep_msg->dg_size);


                if (data_ptr == NULL) {

                    kfw_controls->AUX_policy_st_ptr= &kfw_controls->policies[kfw_controls->current_kfw_policies];

                    policy_ptr=kfw_controls->AUX_policy_st_ptr;

                    kfw_controls->current_kfw_policies++;
                    printf("new policy allocated on cache\n");
                }


                for(int i=0;i<kfwp_controls->kfwprep_msg->dg_cnt;i++) {
                    recvmsg(kfwp_controls->sock_fd, &kfwp_controls->msg, 0);
                    if (i == kfwp_controls->kfwprep_msg->dg_cnt - 1) {
                        memcpy((void *) policy_ptr + i * kfwp_controls->kfwprep_msg->dg_size,
                               NLMSG_DATA(kfwp_controls->nlh),
                               sizeof(policy_t) - i * kfwp_controls->kfwprep_msg->dg_size+1);


                    }else
                        memcpy((void *) policy_ptr + i * kfwp_controls->kfwprep_msg->dg_size,
                               NLMSG_DATA(kfwp_controls->nlh), kfwp_controls->kfwprep_msg->dg_size);

                }

                // set consistency flag to 1
                policy_ptr->consistency=1;

                printf("policy name :%s\n",policy_ptr->name);
                printf("currr  :%d\n",policy_ptr->current_data_actions);


                close(kfwp_controls->sock_fd);

                // return number of bytes written to the destination
                return  sizeof(policy_t);

            } else
                printf("success creation of policy no data\n");

        }


        else if(type==0b00000001 || type==0b10000001)
            printf("rule modified(added/deleted/changed) successfully\n");


        else if(type==0b00000011 || type==0b10000011)
            printf("data_with_action modified(added/deleted/changed) successfully\n");



        else if(type == 0b01111110)
            printf("rules cleared successfully\n");

        else if(type == 0b01111111)
            printf("data_with_actions cleared successfully\n");

        else if(type==0b00000100)
            printf("success of service command\n");

        else if(type==0b10000100)
            printf("success of  no service command\n");


    }

    else if((kfwp_controls->kfwprep_msg->status )==0b00000001) {

        if(type==0b00000000)
            printe("Cannot change type for data %s\nTo change the type first delete the type and recreate it"); //TODO‌


        else if(type==0b00000011)
            printe("Data does not exis"); //TODO‌


        else if(type==0b10000010) {
            printf("an ingress policy relies on the policy\n");
            close(kfwp_controls->sock_fd);
            // return one is just to tell that the policy has not been deleted
            // and it is useful to find out whether should we delete the cache or not
            return 1;
        }
        else if(type == 0b00000100)
            printf("policy_name does not exist for service command\n");




    }

    else if ((kfwp_controls->kfwprep_msg->status)==0b00000010){
        if(type==0b10000000) {
            printf("the data_name does not exist to delete\n");
            close(kfwp_controls->sock_fd);
            // return one is just to tell that the data has not been deleted
            // and it is useful to find out whether should we delete the cache or not
            return 1;
        }

        else if(type==0b10000010) {
            printf("an egress policy relies on the policy\n");
            close(kfwp_controls->sock_fd);
            // return one is just to tell that the policy has not been deleted
            // and it is useful to find out whether should we delete the cache or not
            return 1;

        }


        else if(type==0b10000100)
            printf("policy_name exist on kfw but was not set on this interface in this direction");


    }

    else if ((kfwp_controls->kfwprep_msg->status)==0b00000011){
        if(type==0b10000000) {
            printf(" policy dependency , cannot delete data \n");
            close(kfwp_controls->sock_fd);
            // return one is just to tell that the data has not been deleted
            // and it is useful to find out whether should we delete the cache or not
            return 1;
        }
        else if(type==0b10000010) {
            printf(" the policy does not exist to delete\n");
            close(kfwp_controls->sock_fd);
            // return one is just to tell that the policy has not been deleted
            // and it is useful to find out whether should we delete the cache or not
            return 1;

        }

    }

    else if((kfwp_controls->kfwprep_msg->status)==0b00000100){
        if(type==0b00000000)
            printf("data name does not exist for show command \n");
        else if(type==0b00000010)
            printf("policy name does not exist for show command \n");

    }

    else if((kfwp_controls->kfwprep_msg->status)==0b10000000){
        if(type==0b00000100)
            printf("policy existed and updated \n");
    }

    close(kfwp_controls->sock_fd);

    return 0;




}

int main() {


    ingress_policies_t ingress_policies;
    egress_policies_t egress_policies;

    consistency_flags_t consistencyFlags;
    consistencyFlags.datas=0;
    consistencyFlags.policies=0;
    consistencyFlags.ingress_policies=0;
    consistencyFlags.egress_policies=0;

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


    setup_kfw_commands_regex(&kfw_regex);

    //---------connecting to kernel-------------
    kfwp_controls_t kfwp_controls;



    // Connection --------------------------------


    while(1){
        printf("kfw> ");
        fgets(kfw_controls.user_command,MAX_LEN_USER_COMMAND,stdin);

        // data definition
        if(regexec(&(kfw_regex.regex_data_definition), kfw_controls.user_command, 0, NULL, 0) ==0) {

            /*
             * When user issues ( data DATA_NAME ) , first we should check our datas cache.
             * If we found a data , we then check its consistency with kernel module.
             *  if it was consistent , it is ok.
             *  else we send kfwp request
             *
             * Else we send kfwp request
             * */


            split_data_definition_command(kfw_controls.user_command, kfw_controls.AUX_data_name, &kfw_controls.AUX_data_type,1,0);


            // check existence of a data with name specified by command which is stored in AUX_data_name.
            // If it does exist we get index of it , else we get -1.
            kfw_controls.AUX_functions_returns=get_index_of_data_in_datas(&kfw_controls, kfw_controls.AUX_data_name);


            // A data with type AUX_data_name does not exist so we send kfwp request to kernel
            // to create new one
            if(kfw_controls.AUX_functions_returns == -1){
                printf("new\n");
                kfw_controls.AUX_data_st_ptr=&kfw_controls.datas[kfw_controls.current_kfw_datas];

                kfw_controls.AUX_functions_returns=send_to_kernel(NULL,&kfw_controls,&kfwp_controls,0b00000000,kfw_controls.AUX_data_name,&kfw_controls.AUX_data_type,NULL,kfw_controls.AUX_data_st_ptr,NULL);


                printf("bytes:%d\n",kfw_controls.AUX_functions_returns);
                // if we had bytes written to that address
                if(kfw_controls.AUX_functions_returns !=0){
                    kfw_controls.AUX_data_st_ptr->consistency=1;
                    kfw_controls.current_kfw_datas++;
                }

                else
                    kfw_controls.AUX_data_st_ptr=NULL;


                // set datas array consistancy to 0 because a new data
                // was created
                consistencyFlags.datas=1;

            }
            else {
                printf("exist on cache\n");


                printf("chera %d",kfw_controls.datas[kfw_controls.AUX_functions_returns].consistency);
                if(kfw_controls.datas[kfw_controls.AUX_functions_returns].consistency==1){
                    /* We should check whether data_type specified by user_command matches
                     * data_type of the data we have found.
                     *
                     * Users Cannot change the type whenever they enter data definition mode.
                    */
                    if(kfw_controls.datas[kfw_controls.AUX_functions_returns].type != kfw_controls.AUX_data_type){
                        printe("Cannot change type for data %s\nTo change the type first delete the type and recreate it"); //TODO‌
                        continue;
                    }
                    else
                        kfw_controls.AUX_data_st_ptr = &(kfw_controls.datas[kfw_controls.AUX_functions_returns]);
                }
                else{
                    printf("consistency was failed / send request to kernel\n");
                    kfw_controls.AUX_data_st_ptr=&kfw_controls.datas[kfw_controls.current_kfw_datas];

                    kfw_controls.AUX_functions_returns=send_to_kernel(NULL,&kfw_controls,&kfwp_controls,0b00000000,kfw_controls.AUX_data_name,&kfw_controls.AUX_data_type,NULL,kfw_controls.AUX_data_st_ptr,NULL);

                    kfw_controls.AUX_data_st_ptr->consistency=1;

                    if(kfw_controls.AUX_functions_returns==0)
                        kfw_controls.AUX_data_st_ptr->current_rules=0;

                    // set datas array consistancy to 0 because the data probable
                    // changed //TODO
                    consistencyFlags.datas=0;

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
                    split_rule_definition_command(kfw_controls.user_command, kfw_controls.AUX_rule_type,
                                                  kfw_controls.AUX_rule_value, 0, 1);

                    printf("%s\n", kfw_controls.AUX_data_name);
                    // send request for the rule
                    send_to_kernel(NULL,&kfw_controls, &kfwp_controls, 0b00000001, kfw_controls.AUX_rule_type,
                                   kfw_controls.AUX_rule_value, kfw_controls.AUX_data_name,
                                   &kfw_controls.datas[kfw_controls.AUX_functions_returns], NULL);

                    printf("rule sent\n");


                    //set consistency flag to 0
                    if(kfw_controls.AUX_data_st_ptr!=NULL) {
                        kfw_controls.AUX_data_st_ptr->consistency = 0;
                        printf("inconsistent\n");
                    }

                    // set datas array consistancy to 0
                    consistencyFlags.datas=0;


                }
                // rule deletion
                else if (regexec(&kfw_regex.regex_rule_deletion, kfw_controls.user_command, 0, NULL, 0) == 0) {

                    onebyte_p_t rule_type[MAX_LEN_RULE_TYPE];
                    onebyte_p_t rule_value[MAX_LEN_RULE_VALUE];
                    bzero(rule_type, MAX_LEN_RULE_TYPE);
                    bzero(rule_value, MAX_LEN_RULE_VALUE);

                    split_rule_definition_command(kfw_controls.user_command, rule_type, rule_value, 1, 2);


                    // send request to kernel
                    send_to_kernel(NULL,&kfw_controls, &kfwp_controls, 0b10000001, kfw_controls.AUX_rule_type,
                                   kfw_controls.AUX_rule_value, kfw_controls.AUX_data_name,
                                   &kfw_controls.datas[kfw_controls.AUX_functions_returns], NULL);

                    //set consistency flag to 0
                    if(kfw_controls.AUX_data_st_ptr!=NULL) {
                        kfw_controls.AUX_data_st_ptr->consistency = 0;
                        printf("inconsistent\n");
                    }
                    // set datas array consistancy to 0
                    consistencyFlags.datas=0;

                }

                    // quick clear
                else if (regexec(&kfw_regex.regex_quick_clear, kfw_controls.user_command, 0, NULL, 0) == 0) {
                    // send request to kernel // TODO‌ arg1 arg2 not necessary
                    send_to_kernel(NULL,&kfw_controls, &kfwp_controls, 0b01111110, "NULL","NULL", "NULL",NULL,NULL);

                    //set consistency flag to 0
                    if(kfw_controls.AUX_data_st_ptr!=NULL) {
                        kfw_controls.AUX_data_st_ptr->consistency = 0;
                        printf("inconsistent\n");
                    }
                    // set datas array consistancy to 0
                    consistencyFlags.datas=0;

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
                        kfw_controls.AUX_functions_returns=send_to_kernel(NULL,&kfw_controls,&kfwp_controls,0b00000000,kfw_controls.AUX_data_name,&kfw_controls.AUX_data_type,NULL,kfw_controls.AUX_data_st_ptr,NULL);

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
                        kfw_controls.AUX_functions_returns=send_to_kernel(NULL,&kfw_controls,&kfwp_controls,0b00000000,kfw_controls.AUX_data_name,&kfw_controls.AUX_data_type,NULL,kfw_controls.AUX_data_st_ptr,NULL);
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
            split_policy_definition_command(kfw_controls.user_command,kfw_controls.AUX_policy_name,1,0);


            kfw_controls.AUX_functions_returns=get_index_of_policy_in_policies(&kfw_controls, kfw_controls.AUX_policy_name);


            // A policy with name AUX_policy_name does not exist so we allocate new one in
            // kfw_controls.policies
            if(kfw_controls.AUX_functions_returns == -1){

                printf("policy not exist on cache\n");

                printf("send request\n");

                kfw_controls.AUX_policy_st_ptr=&kfw_controls.policies[kfw_controls.current_kfw_policies];

                kfw_controls.AUX_functions_returns=send_to_kernel(NULL,&kfw_controls,&kfwp_controls,0b00000010,kfw_controls.AUX_policy_name,NULL,NULL,NULL,kfw_controls.AUX_policy_st_ptr);


                printf("policy bytes:%d\n",kfw_controls.AUX_functions_returns);

                // if we had bytes written to that address
                if(kfw_controls.AUX_functions_returns !=0)
                    kfw_controls.current_kfw_policies++;
                else
                    kfw_controls.AUX_policy_st_ptr=NULL;

                // set policies array consistancy to 0 because the policy probabaly
                // created/entered with no data
                consistencyFlags.policies=0;

            }
            else {
                printf("policy exist on cache\n");

                if(kfw_controls.policies[kfw_controls.AUX_functions_returns].consistency==1){

                        kfw_controls.AUX_policy_st_ptr = &(kfw_controls.policies[kfw_controls.AUX_functions_returns]);
                }
                else{
                    printf("consistency was failed / send request to kernel\n");

                    kfw_controls.AUX_policy_st_ptr=&kfw_controls.policies[kfw_controls.current_kfw_policies];

                    send_to_kernel(NULL,&kfw_controls,&kfwp_controls,0b00000010,kfw_controls.AUX_policy_name,NULL,NULL,NULL,kfw_controls.AUX_policy_st_ptr);

                    kfw_controls.AUX_policy_st_ptr->consistency=1;

                    // set policies array consistancy to 0 because the policy probabaly
                    // changed
                    consistencyFlags.policies=0;


                }

            }


            while(1) {
                printf("kfw-policy> ");
                // Clear the user command.Make all the written bytes zero
                bzero(kfw_controls.user_command,strlen(kfw_controls.user_command));

                fgets(kfw_controls.user_command, MAX_LEN_USER_COMMAND, stdin);

                // data_action definition( with overwrite ability )
                if (regexec(&kfw_regex.regex_data_action_definition, kfw_controls.user_command, 0, NULL, 0) == 0) {
                    split_data_with_action_command(kfw_controls.user_command,kfw_controls.AUX_data_name,kfw_controls.AUX_action_name,0,1);



                    send_to_kernel(NULL,&kfw_controls, &kfwp_controls, 0b00000011, kfw_controls.AUX_data_name,
                                   kfw_controls.AUX_action_name, "NULL",
                                   NULL,&kfw_controls.policies[kfw_controls.AUX_functions_returns]);



                    printf("data with action sent\n");

                    //set consistency flag to 0
                    if(kfw_controls.AUX_policy_st_ptr!=NULL) {
                        kfw_controls.AUX_policy_st_ptr->consistency = 0;
                        printf("inconsistent\n");
                    }

                    // set policies array consistancy to 0 because the policy probabaly
                    // changed
                    consistencyFlags.policies=0;

                }

                else if (regexec(&kfw_regex.regex_back_to_previous_mode, kfw_controls.user_command, 0, NULL, 0) ==0) {
                    break;
                }

                    // data_action deletion
                else if (regexec(&kfw_regex.regex_data_action_deletion, kfw_controls.user_command, 0, NULL, 0) ==0) {

                    split_data_with_action_command(kfw_controls.user_command,kfw_controls.AUX_data_name,kfw_controls.AUX_action_name,1,2);


                    send_to_kernel(NULL,&kfw_controls, &kfwp_controls, 0b10000011, kfw_controls.AUX_data_name,
                                   kfw_controls.AUX_action_name, "NULL",
                                   NULL,&kfw_controls.policies[kfw_controls.AUX_functions_returns]);

                    //set consistency flag to 0
                    if(kfw_controls.AUX_policy_st_ptr!=NULL) {
                        kfw_controls.AUX_policy_st_ptr->consistency = 0;
                        printf("inconsistent\n");
                    }
                    // set policies array consistancy to 0 because the policy probabaly
                    // changed
                    consistencyFlags.policies=0;


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
                            kfw_controls.AUX_functions_returns=send_to_kernel(NULL,&kfw_controls,&kfwp_controls,0b00000010,kfw_controls.AUX_data_name,&kfw_controls.AUX_data_type,NULL,NULL,kfw_controls.AUX_policy_st_ptr);

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
                        kfw_controls.AUX_functions_returns=send_to_kernel(NULL,&kfw_controls,&kfwp_controls,0b00000010,kfw_controls.AUX_data_name,&kfw_controls.AUX_data_type,NULL,NULL,kfw_controls.AUX_policy_st_ptr);
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
                    send_to_kernel(NULL,&kfw_controls, &kfwp_controls, 0b01111111, "NULL","NULL", "NULL",NULL,NULL);

                    //set consistency flag to 0
                    if(kfw_controls.AUX_policy_st_ptr!=NULL) {
                        kfw_controls.AUX_policy_st_ptr->consistency = 0;
                        printf("inconsistent\n");
                    }
                    // set policies array consistancy to 0 because the policy probabaly
                    // changed
                    consistencyFlags.policies=0;


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
            split_data_definition_command(kfw_controls.user_command, kfw_controls.AUX_data_name, &kfw_controls.AUX_data_type,2,2);

            // send deletion request to kernel
            kfw_controls.AUX_functions_returns=send_to_kernel(NULL,&kfw_controls,&kfwp_controls,0b10000000,kfw_controls.AUX_data_name,&kfw_controls.AUX_data_type,NULL,NULL,NULL);


            // when we delete the data from cache
            // we do not change datas array consistancy flag
            // thats because we don't see any request be generated by kfw

            // successful deletion of data in kernel
            if(kfw_controls.AUX_functions_returns==0){
                kfw_controls.AUX_functions_returns=get_index_of_data_in_datas(&kfw_controls, kfw_controls.AUX_data_name);

                if(kfw_controls.AUX_functions_returns != -1){
                    // Delte the data from the cache
                    // Delete the data from datas array.
                    // Deletion policy is same as before.
                    if(kfw_controls.AUX_functions_returns == kfw_controls.current_kfw_datas - 1) {
                        if (kfw_controls.current_kfw_datas - 1 != -1)
                            kfw_controls.current_kfw_datas--;
                    }
                    else{
                        kfw_controls.AUX_functions_returns++;
                        while(kfw_controls.AUX_functions_returns <= kfw_controls.current_kfw_datas - 1){
                            memcpy(&kfw_controls.datas[kfw_controls.AUX_functions_returns - 1], &kfw_controls.datas[kfw_controls.AUX_functions_returns], sizeof(data_t));
                            kfw_controls.AUX_functions_returns++;
                        }
                        //update total number of datas
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
            split_policy_definition_command(kfw_controls.user_command,kfw_controls.AUX_policy_name,2,2);


            kfw_controls.AUX_functions_returns=send_to_kernel(NULL,&kfw_controls,&kfwp_controls,0b10000010,kfw_controls.AUX_policy_name,NULL,NULL,NULL,NULL);



            kfw_controls.AUX_functions_returns=get_index_of_policy_in_policies(&kfw_controls, kfw_controls.AUX_policy_name);

            // deletion policy is same as before
            if(kfw_controls.AUX_functions_returns != -1){
                if(kfw_controls.AUX_functions_returns == kfw_controls.current_kfw_policies - 1) {
                    if(kfw_controls.current_kfw_policies-1!=-1)
                        kfw_controls.current_kfw_policies--;


                }
                else{
                    kfw_controls.AUX_functions_returns++;
                    while(kfw_controls.AUX_functions_returns <= kfw_controls.current_kfw_policies - 1){
                        memcpy(&kfw_controls.policies[kfw_controls.AUX_functions_returns - 1], &kfw_controls.policies[kfw_controls.AUX_functions_returns], sizeof(policy_t));
                        kfw_controls.AUX_functions_returns++;
                    }
                    //update total number of policies
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

            split_data_definition_command(kfw_controls.user_command, kfw_controls.AUX_data_name, &kfw_controls.AUX_data_type,2,4);

            kfw_controls.AUX_functions_returns=get_index_of_data_in_datas(&kfw_controls, kfw_controls.AUX_data_name);

            if(kfw_controls.AUX_functions_returns == -1) {
                printf("new\n");
                kfw_controls.AUX_data_st_ptr=&kfw_controls.datas[kfw_controls.current_kfw_datas];


                // by setting type to 2 , we tell kernel not to check the type
                // and send us data
                kfw_controls.AUX_data_type=2;
                kfw_controls.AUX_functions_returns=send_to_kernel(NULL,&kfw_controls,&kfwp_controls,0b00000000,kfw_controls.AUX_data_name,&kfw_controls.AUX_data_type,NULL,kfw_controls.AUX_data_st_ptr,NULL);


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

                if(kfw_controls.datas[kfw_controls.AUX_functions_returns].consistency==1){

                        printf("show data XXX consists\n");
                        kfw_controls.AUX_data_st_ptr = &(kfw_controls.datas[kfw_controls.AUX_functions_returns]);
                }
                else{
                    printf("show data XXX consistency was failed / send request to kernel\n");
                    kfw_controls.AUX_data_st_ptr=&kfw_controls.datas[kfw_controls.current_kfw_datas];

                    // by setting type to 2 , we tell kernel not to check the type
                    // and send us data
                    kfw_controls.AUX_data_type=2;
                    kfw_controls.AUX_functions_returns=send_to_kernel(NULL,&kfw_controls,&kfwp_controls,0b00000000,kfw_controls.AUX_data_name,&kfw_controls.AUX_data_type,NULL,kfw_controls.AUX_data_st_ptr,NULL);

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


            split_policy_definition_command(kfw_controls.user_command,kfw_controls.AUX_policy_name,2,4);

            kfw_controls.AUX_functions_returns=get_index_of_policy_in_policies(&kfw_controls, kfw_controls.AUX_policy_name);



            if(kfw_controls.AUX_functions_returns == -1) {

                printf("policy not exist on cache\n");

                printf("send request\n");

                kfw_controls.AUX_policy_st_ptr=&kfw_controls.policies[kfw_controls.current_kfw_policies];

                // setting arg2 for kernel means we are issuing
                // show policy POLICY_NAME command
                kfw_controls.AUX_functions_returns=send_to_kernel(NULL,&kfw_controls,&kfwp_controls,0b00000010,kfw_controls.AUX_policy_name,"show",NULL,NULL,kfw_controls.AUX_policy_st_ptr);


                printf("policy bytes:%d\n",kfw_controls.AUX_functions_returns);

                // if we had bytes written to that address
                if(kfw_controls.AUX_functions_returns !=0)
                    kfw_controls.current_kfw_policies++;
                else
                    kfw_controls.AUX_policy_st_ptr=NULL;

            }else{
                //check consistency
                printf("show policy XXX exist on cache\n");

                if(kfw_controls.policies[kfw_controls.AUX_functions_returns].consistency==1){

                    printf("show policy XXX consists\n");
                    kfw_controls.AUX_policy_st_ptr = &(kfw_controls.policies[kfw_controls.AUX_functions_returns]);
                }
                else{
                    printf("show policy XXX consistency was failed / send request to kernel\n");

                    kfw_controls.AUX_policy_st_ptr=&kfw_controls.policies[kfw_controls.current_kfw_policies];

                    send_to_kernel(NULL,&kfw_controls,&kfwp_controls,0b00000010,kfw_controls.AUX_policy_name,NULL,NULL,NULL,kfw_controls.AUX_policy_st_ptr);


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

            printf("service policy definition\n");
            split_service_policy_command(kfw_controls.user_command,kfw_controls.AUX_policy_name,
                                         kfw_controls.AUX_interface_name,kfw_controls.AUX_policy_direction,1,2,3);

            kfw_controls.AUX_functions_returns=send_to_kernel(NULL,&kfw_controls,&kfwp_controls,0b00000100,kfw_controls.AUX_policy_name,kfw_controls.AUX_interface_name,kfw_controls.AUX_policy_direction,NULL,NULL);

        }

        // service policy deletion
        else if (regexec(&kfw_regex.regex_service_policy_deletion, kfw_controls.user_command, 0, NULL, 0) ==0) {

            printf("service policy deletion\n");



            split_service_policy_command(kfw_controls.user_command,kfw_controls.AUX_policy_name,
                                         kfw_controls.AUX_interface_name,kfw_controls.AUX_policy_direction,2,3,4);


            kfw_controls.AUX_functions_returns=send_to_kernel(NULL,&kfw_controls,&kfwp_controls,0b10000100,kfw_controls.AUX_policy_name,kfw_controls.AUX_interface_name,kfw_controls.AUX_policy_direction,NULL,NULL);


            kfw_controls.AUX_functions_returns=get_index_of_policy_in_policies(&kfw_controls, kfw_controls.AUX_policy_name);

            if(kfw_controls.AUX_functions_returns == -1)
                printe("Policy %s does not exist\n"); //TODO
            else{
                // TODO‌ make this code better
                if(strcmp(kfw_controls.AUX_policy_direction,"out")==0) {

                    kfw_controls.AUX_functions_returns = get_index_of_policyint_in_egress(&egress_policies, kfw_controls.AUX_policy_name, kfw_controls.AUX_interface_name);

                    if(kfw_controls.AUX_functions_returns != -1){

                        // Deletion policy is like before
                        if(kfw_controls.AUX_functions_returns == egress_policies.current_egress_policies - 1){
                            if(egress_policies.current_egress_policies-1!=-1)
                                egress_policies.current_egress_policies--;
                        }
                        else{
                            kfw_controls.AUX_functions_returns++;
                            while(kfw_controls.AUX_functions_returns <= egress_policies.current_egress_policies - 1){
                                memcpy(&egress_policies.policyWithInterfaces[kfw_controls.AUX_functions_returns - 1], &egress_policies.policyWithInterfaces[kfw_controls.AUX_functions_returns], sizeof(policy_with_int_t));
                                kfw_controls.AUX_functions_returns++;
                            }
                            // update total number of policy_with_int
                            egress_policies.current_egress_policies--;
                        }
                        printf("deleted successfully\n");

                    }

                }
                else{

                    kfw_controls.AUX_functions_returns = get_index_of_policyint_in_ingress(&ingress_policies, kfw_controls.AUX_policy_name, kfw_controls.AUX_interface_name);


                    if(kfw_controls.AUX_functions_returns != -1){
                        // Deletion policy is like before
                        if(kfw_controls.AUX_functions_returns == ingress_policies.current_ingress_policies - 1){
                            if(ingress_policies.current_ingress_policies-1!=-1)
                                ingress_policies.current_ingress_policies--;
                        }
                        else{
                            kfw_controls.AUX_functions_returns++;
                            while(kfw_controls.AUX_functions_returns <= ingress_policies.current_ingress_policies - 1){
                                memcpy(&ingress_policies.policyWithInterfaces[kfw_controls.AUX_functions_returns - 1], &ingress_policies.policyWithInterfaces[kfw_controls.AUX_functions_returns], sizeof(policy_with_int_t));
                                kfw_controls.AUX_functions_returns++;
                            }
                            // update total number of policy_with_int
                            ingress_policies.current_ingress_policies--;

                        }
                        printf("deleted successfully\n");
                    }
                }
            }
        }




        // show polices
        else if (regexec(&kfw_regex.regex_show_polices, kfw_controls.user_command, 0, NULL, 0) ==0) {

            //first check policies cache consistency

            // if policies was not consitent
            if(consistencyFlags.policies==0){
                // first clear datas cache
                bzero(&kfw_controls.policies,10*sizeof(policy_t)); //TODO change 10 as macro

                // send request to kernel
                kfw_controls.AUX_functions_returns=send_to_kernel(&consistencyFlags,&kfw_controls,&kfwp_controls,0b00001111,NULL,NULL,NULL,NULL,NULL);

            }



            printf("policies\n");
            printf("-----------------\n");
            for(int i=0;i<kfw_controls.current_kfw_policies;i++)
                printf("policy %s\n",kfw_controls.policies[i].name);
        }






        // ingress  /  egress
        // show polices (in|out)
        else if (regexec(&kfw_regex.regex_show_polices_with_dir, kfw_controls.user_command, 0, NULL, 0) ==0) {
            split_string_with_position(kfw_controls.user_command,2,kfw_controls.AUX_policy_direction);

            if(strcmp(kfw_controls.AUX_policy_direction,"in")==0) {
                printf("ingress policies\n");
                printf("-----------------\n");
                for (int i = 0; i < ingress_policies.current_ingress_policies; i++)
                    printf("%s , %s\n", ingress_policies.policyWithInterfaces[i].policy_name,
                           ingress_policies.policyWithInterfaces[i].interface_name);
            }
            else {
                printf("egress policies\n");
                printf("-----------------\n");
                for(int i=0;i<egress_policies.current_egress_policies;i++)
                    printf("%s , %s\n",egress_policies.policyWithInterfaces[i].policy_name,egress_policies.policyWithInterfaces[i].interface_name);

            }
        }

        // show polices (INTERFACE)
        else if (regexec(&kfw_regex.regex_show_policies_with_int, kfw_controls.user_command, 0, NULL, 0) ==0) {
            split_string_with_position(kfw_controls.user_command, 2, kfw_controls.AUX_interface_name);

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

        // show policies ( INTERFACE‌ ) (in | out)
        else if (regexec(&kfw_regex.regex_show_policies_with_int_dir, kfw_controls.user_command, 0, NULL, 0) ==0) {
            //TODO‌ make one function
            //TODO make for to a function
            split_string_with_position(kfw_controls.user_command, 2, kfw_controls.AUX_interface_name);
            split_string_with_position(kfw_controls.user_command, 3, kfw_controls.AUX_policy_direction);

            printf("Interface : %s\n", kfw_controls.AUX_interface_name);
            if(strcmp(kfw_controls.AUX_policy_direction,"in")==0) {
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





        // show datas
        else if (regexec(&kfw_regex.regex_show_datas, kfw_controls.user_command, 0, NULL, 0) ==0) {

            //first check datas cache consistency

            // if datas was not consitent
            if(consistencyFlags.datas==0){
                // first clear datas cache
                bzero(&kfw_controls.datas,10*sizeof(data_t)); //TODO change 10 as macro

                // send request to kernel
                kfw_controls.AUX_functions_returns=send_to_kernel(&consistencyFlags,&kfw_controls,&kfwp_controls,0b00001110,NULL,NULL,NULL,NULL,NULL);

            }


            //TODO fields of output
            printf("--------DATAS-------\n");

            for(int i=0;i<kfw_controls.current_kfw_datas;i++){
                if(kfw_controls.datas[i].type==1)
                    printf("%s (all)\n",kfw_controls.datas[i].name);
                else
                    printf("%s (any)\n",kfw_controls.datas[i].name);

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

onebyte_np_t get_index_of_rule_in_rules(data_t *data_st ,onebyte_p_t *rule_type ){
    for(int i=0;i<data_st->current_rules;i++){
        if (strncmp(data_st->rules[i].type, rule_type, strlen(rule_type)) == 0)
            return i;
    }
    return -1;


}

onebyte_np_t get_index_of_policyint_in_egress(egress_policies_t *egressPolicies , onebyte_p_t *policy_name , onebyte_p_t*interface_name){

    for(int i=0;i<egressPolicies->current_egress_policies;i++){
        if(strncmp(egressPolicies->policyWithInterfaces[i].policy_name,policy_name,strlen(policy_name))==0
           && strcmp(egressPolicies->policyWithInterfaces[i].interface_name,interface_name)==0)

            return i;
    }
    return -1;

}

onebyte_np_t get_index_of_policyint_in_ingress(ingress_policies_t *ingressPolicies , onebyte_p_t *policy_name ,onebyte_p_t *interface_name){

    for(int i=0;i<ingressPolicies->current_ingress_policies;i++){
        if(strncmp(ingressPolicies->policyWithInterfaces[i].policy_name,policy_name,strlen(policy_name))==0
           && strcmp(ingressPolicies->policyWithInterfaces[i].interface_name,interface_name)==0)
            return i;
    }
    return -1;

}

onebyte_np_t get_index_of_datawithaction_in_policies(policy_t *policy , onebyte_p_t *data_name){
    for(int i=0;i<policy->current_data_actions;i++){
        if(strncmp(policy->data_with_actions[i].data_name,data_name,strlen(data_name))==0)
            return i;
    }
    return -1;
}

onebyte_np_t get_index_of_data_in_datas(kfw_controls_t *kfw_controls,onebyte_p_t *data_name){

    for(int i=0;i<kfw_controls->current_kfw_datas;i++)
        if(strncmp(kfw_controls->datas[i].name,data_name,strlen(data_name))==0){
            return i;
        }
    return -1;

}

onebyte_np_t get_index_of_policy_in_policies(kfw_controls_t *kfw_controls,onebyte_p_t *policy_name){

    for(int i=0;i<kfw_controls->current_kfw_policies;i++)
        if(strncmp(kfw_controls->policies[i].name,policy_name,strlen(policy_name))==0){
            return i;
        }
    return -1;

}


void split_string_with_position(onebyte_p_t *str,onebyte_p_t position , onebyte_p_t * dst){
    bzero(dst,strlen(dst));
    onebyte_p_t element_pos=-1;
    onebyte_p_t *temp;
    while(*str){
        if(*str==32 || *str==10 || *str==9)
            str++;
        else{
            element_pos++;
            if(element_pos==position){
                temp=str;
                while (*str != 32 && *str != 10 && *str != 9)
                    str++;
                memcpy(dst,temp,str-temp);
                break;
            }
            else
                while (*str != 32 && *str != 10 && *str != 9)
                    str++;
        }
    }
}

void split_service_policy_command(onebyte_p_t *service_policy_cmd,onebyte_p_t *policy_name,onebyte_p_t *interface_name ,onebyte_p_t * direction,
                                  onebyte_p_t policy_name_pos ,onebyte_p_t interface_name_pos,onebyte_p_t direction_pos){


    // service asd
    onebyte_p_t service_policy_command_ele=-1;
    onebyte_p_t *temp;

    bzero(policy_name,strlen(policy_name));
    bzero(interface_name,strlen(interface_name));
    bzero(direction,strlen(direction));

    while(*service_policy_cmd){
        if(*service_policy_cmd==32 || *service_policy_cmd==10 || *service_policy_cmd==9)
            service_policy_cmd++;
        else{
            service_policy_command_ele++;
            if(service_policy_command_ele==0 && policy_name_pos==2)
                service_policy_cmd+=2;  // skipping (no) in negative form

            else if((service_policy_command_ele==0 && policy_name_pos==1)||(service_policy_command_ele==1 && policy_name_pos==2))
                service_policy_cmd+=7;  // skipping (service) in positive and negative form

            else{
                temp=service_policy_cmd;
                while(*service_policy_cmd!=32 && *service_policy_cmd!=10 && *service_policy_cmd!=9)
                    service_policy_cmd++;

                if(service_policy_command_ele==policy_name_pos)
                    memcpy(policy_name,temp,service_policy_cmd-temp);

                else if(service_policy_command_ele==interface_name_pos)
                    memcpy(interface_name,temp,service_policy_cmd-temp);

                else  if(service_policy_command_ele==direction_pos)
                    memcpy(direction,temp,service_policy_cmd-temp);
            }

//            else if(service_policy_command_ele==action_pos){
//                temp=service_policy_cmd;
//                while(*service_policy_cmd!=32 && *service_policy_cmd!=10 && *service_policy_cmd!=9)
//                    service_policy_cmd++;
//                memcpy(action,temp,service_policy_cmd-temp);
//                // we put break to end the function at this point because
//                // we have collected all the things we need
//                break;
//            }
        }

    }
}

void split_data_with_action_command(onebyte_p_t *data_with_action_cmd,onebyte_p_t *data_name,onebyte_p_t *action , onebyte_p_t data_name_pos ,onebyte_p_t action_pos){
    onebyte_p_t data_with_action_command_ele=-1;
    onebyte_p_t *temp;

    // TODO‌ do this on other functions of splitting
    bzero(data_name,strlen(data_name));
    bzero(action,strlen(action));

    while(*data_with_action_cmd){
        if(*data_with_action_cmd==32 || *data_with_action_cmd==10 || *data_with_action_cmd==9)
            data_with_action_cmd++;
        else{
            data_with_action_command_ele++;
            if(data_with_action_command_ele==0 && data_name_pos==1)
                data_with_action_cmd+=2;
            else if(data_with_action_command_ele==data_name_pos){
                temp=data_with_action_cmd;
                while(*data_with_action_cmd!=32 && *data_with_action_cmd!=10 && *data_with_action_cmd!=9)
                    data_with_action_cmd++;
                memcpy(data_name,temp,data_with_action_cmd-temp);
            }
            else if(data_with_action_command_ele==action_pos){
                temp=data_with_action_cmd;
                while(*data_with_action_cmd!=32 && *data_with_action_cmd!=10 && *data_with_action_cmd!=9)
                    data_with_action_cmd++;
                memcpy(action,temp,data_with_action_cmd-temp);
                // we put break to end the function at this point because
                // we have collected all the things we need
                break;
            }
        }

    }
}

void split_policy_definition_command(onebyte_p_t *policy_def,onebyte_p_t *policy_name , onebyte_p_t name_pos ,onebyte_p_t show_or_no_len){

    onebyte_p_t policy_command_ele=-1;
    onebyte_p_t *temp;
    while(*policy_def){
        if(*policy_def==32 || *policy_def==10 || *policy_def==9)
            policy_def++;
        else{
            policy_command_ele++;
            if(policy_command_ele==0 && name_pos==2)
                policy_def += show_or_no_len;    // skipping (show/no) which is (4/2) characters and specified by onebyte_p_t show_or_no_len

                // we have to skip (policy) in two cases :
                // 1: we have positive form which (policy) is the first element ( name_pos = 1 , policy_pos = 0 )
                //                 or
                // 2: we have negative form which‌ (policy) is the second element ( name_pos = 2 , policy_pos = 1 )
            else if((policy_command_ele==0 && name_pos==1) || (policy_command_ele==1 && name_pos==2))
                policy_def += 6;   // skipping (policy) which is 6 characters

            else if(policy_command_ele==name_pos){
                temp=policy_def;
                while(*policy_def!=32 && *policy_def!=10 && *policy_def!=9)
                    policy_def++;
                memcpy(policy_name,temp,policy_def-temp);
                // we put break to end the function at this point because
                // we have collected all the things we need
                break;
            }
        }

    }
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

void split_data_definition_command(onebyte_p_t * data_def , onebyte_p_t *data_name ,onebyte_p_t *type , onebyte_p_t data_name_pos ,onebyte_p_t show_or_no_len){
    /*
     * show_or_no_len==0 means don't care
     * */

    onebyte_p_t data_command_ele=-1;
    onebyte_p_t *temp;

    bzero(data_name,strlen(data_name));

    while(*data_def){
        if(*data_def==32 || *data_def==10 || *data_def==9)
            data_def++;
        else{
            data_command_ele++;
            // skipping (data) which is 4 bytes
            // skipping (data) :
            //    when command is in positive form > (data) is at pos 0 && data_name is at pos 1
            //    when command is in negative form > (data) is at pos 1 && data_name is at pos 2

            if((data_command_ele==0 && data_name_pos==1) || (data_command_ele==1 && data_name_pos==2))
                data_def+=4;

            else if((data_command_ele==0 && data_name_pos==2))
                data_def+=show_or_no_len;     // skipping (show/no) which is (4/2) bytes and is specified by show_or_no_len

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
                else if(strncmp(data_def,"any",3)==0){
                    *type=0;
                    break;
                }
            }

        }
    }
    // if the user don't specify the type , default type is 0 which is match any
    if(data_command_ele!=3)
        *type=0;

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

    if (regcomp(&kfwregex->regex_service_policy_definition,REGEX_SERVICE_POLICY_DEFINITION,REG_EXTENDED) != 0) {
        printe("service_policy_definition regex compilation error");
    }
    if (regcomp(&kfwregex->regex_service_policy_deletion,REGEX_SERVICE_POLICY_DELETION,REG_EXTENDED) != 0) {
        printe("service_policy_deletion regex compilation error");
    }

    if (regcomp(&kfwregex->regex_show_polices,REGEX_SHOW_POLICIES,REG_EXTENDED) != 0) {
        printe("show_policies regex compilation error");
    }
    if (regcomp(&kfwregex->regex_show_polices_with_dir,REGEX_SHOW_POLICIES_WITH_DIRECTION,REG_EXTENDED) != 0) {
        printe("show_policies_with_dir regex compilation error");
    }

    if (regcomp(&kfwregex->regex_show_policies_with_int,REGEX_SHOW_POLICIES_WITH_INTERFACE,REG_EXTENDED) != 0) {
        printe("show_policies_with_int regex compilation error");
    }

    if (regcomp(&kfwregex->regex_show_policies_with_int_dir,REGEX_SHOW_POLICIES_WITH_INTERFACE_DIR,REG_EXTENDED) != 0) {
        printe("show_policies_with_int_dir regex compilation error");
    }

    if (regcomp(&kfwregex->regex_show_datas,REGEX_SHOW_DATAS,REG_EXTENDED) != 0) {
        printe("show_datas regex compilation error");
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
    if (regcomp(&kfwregex->regex_data_action_deletion,REGEX_DATA_ACTION_DELETION,REG_EXTENDED) != 0) {
        printe("data_action_deletion regex compilation error");
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


