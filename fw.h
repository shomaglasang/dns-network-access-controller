/*INC+*************************************************************************/
/* Filename    : fw.h                                                         */
/*                                                                            */
/* Description : Firewall routines contants, decls, header file.              */
/*                                                                            */
/* Revisions   : 06/07/14  Sho                                                */
/*                         - Creation.                                        */
/*                                                                            */
/*INC+*************************************************************************/

#ifndef _FW_H
#define _FW_H

/******************************************************************************/
/* Contants.                                                                  */
/******************************************************************************/
#define FW_RULE_TAG                               "DNSWLD"
#define FW_ACCEPT_RULE                            0
#define FW_DROP_RULE                              1

#define DNSWLD_FW_DUMP                            "/tmp/dnswldfw.dump"

/******************************************************************************/
/* Forward decls.                                                             */
/******************************************************************************/
extern int add_fw_rule(unsigned int s_ip, unsigned int d_ip, int action,
                       unsigned int created_at, unsigned int tt);
extern int del_fw_rule(unsigned int s_ip, unsigned int d_ip, int action,
                       unsigned int created_at, unsigned int tt);
#endif
