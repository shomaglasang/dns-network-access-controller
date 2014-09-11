/*INC+*************************************************************************/
/* Filename    : config.h                                                     */
/*                                                                            */
/* Description : Configuration header file.                                   */
/*                                                                            */
/* Revisions   : 05/10/14  Sho                                                */
/*                         - Creation.                                        */
/*                                                                            */
/*INC+*************************************************************************/

#ifndef _CONFIG_H  
#define _CONFIG_H  

/******************************************************************************/
/* Config keywords.                                                           */
/******************************************************************************/
#define CFG_BIND                                  "bind"
#define CFG_WHITELIST                             "whitelist"
#define CFG_CHAINS                                "chains"
#define CFG_IPTABLES_PATH                         "iptables_path"

/******************************************************************************/
/* Forwards decls.                                                            */
/******************************************************************************/
extern int parse_args(int argc, char **argv);
extern int process_config(void);

#endif

