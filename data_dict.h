/*INC+*************************************************************************/
/* Filename    : data_dic.h                                                   */
/*                                                                            */
/* Description : DNS dictionary header file.                                  */
/*                                                                            */
/* Revisions   : 05/21/14  Sho                                                */
/*                         - Creation.                                        */
/*                                                                            */
/*INC+*************************************************************************/

#ifndef _DATA_DIC_H
#define _DATA_DIC_H

/******************************************************************************/
/* Includes.                                                                  */
/******************************************************************************/
#include <dns.h>

/******************************************************************************/
/* Dictionary types.                                                          */
/******************************************************************************/
#define WHITELIST_NAMES                           1
#define BLACKLIST_NAMES                           2

#define NODE_REG_TYPE                             0
#define NODE_WILDCARD_TYPE                        1

#define ROOT_NODE_NAME                            "root"
#define WILDCARD_NODE_NAME                        "*"

/******************************************************************************/
/* DNS name tree.                                                             */
/******************************************************************************/
typedef struct _dnt_node
{
  struct _dnt_node *h_child;
  struct _dnt_node *t_child;
  struct _dnt_node *next;
  char name[DNS_MAX_LABEL_LEN + 1];
  int type;
} dnt_node;


/******************************************************************************/
/* DNS answer. We set a limit of 10 records for now.                          */
/******************************************************************************/
typedef struct _dns_answer
{
  int n_rec;
  char recs[DNS_MAX_ANS_RR_NUM][DNS_MAX_ANS_RR_LEN];
} dns_answer;


/******************************************************************************/
/* DNS question.                                                              */
/******************************************************************************/
typedef struct _dns_question
{
  int n_label;
  char labels[DNS_MAX_NUM_LABELS][DNS_MAX_LABEL_LEN + 1];
  char name[DNS_MAX_NAME_LEN + 1];
  short q_type;
  short q_class;
  dns_answer ans;
} dns_question;


/******************************************************************************/
/* Forwards decls.                                                            */
/******************************************************************************/
extern int add_name_to_dictionary(char *name, dnt_node *root);
extern int find_name(dns_question *q, dnt_node *root);
extern int create_name_tree(dnt_node **root);
extern void destroy_name_tree(dnt_node **root);

#endif
