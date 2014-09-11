/*FILE+************************************************************************/
/* Filename    : fw.c                                                         */
/*                                                                            */
/* Description : Firewall related routines.                                   */
/*                                                                            */
/* Revisions   : 06/07/14  Sho                                                */
/*                         - Creation.                                        */
/*                                                                            */
/*FILE-************************************************************************/

#include <common.h>
#include <dnswldcb.h>
#include <fw.h>


/*FUNC+************************************************************************/
/* Function    : add_fw_rule                                                  */
/*                                                                            */
/* Description : Add rule to iptables for given source and dest.              */
/*                                                                            */
/* Params      : s_ip (IN)                - Source IP.                        */
/*               d_ip (IN)                - Destination IP.                   */
/*               action (IN)              - Action.                           */
/*               created_at (IN)          - Creation timestamp.               */
/*               expiry (IN)              - Expiry timestamp.                 */
/*                                                                            */
/* Returns     : RET_OK                   - Success otherwise error.          */
/*                                                                            */
/*FUNC-************************************************************************/
int add_fw_rule(unsigned int s_ip, unsigned int d_ip, int action,
                unsigned created_at, unsigned int expiry)
{
  char cmd[1024];
  char tt_str[31] = {0};
  char *action_str;
  int i;
  int ret;

  action_str = (action == FW_ACCEPT_RULE) ? "ACCEPT" : "DROP";
  ctime_r((time_t *)&expiry, tt_str);
  if (strlen(tt_str))
  {
    tt_str[strlen(tt_str) -1] = '\0';
  }

  /****************************************************************************/
  /* Add the rule for each chain.                                             */
  /****************************************************************************/
  for (i = 0; i < dnswld.fw.n_chains; i++)
  {
    snprintf(cmd, sizeof(cmd),
             "%s -A %s -s %d.%d.%d.%d -d %d.%d.%d.%d -j %s "
		     "-m comment --comment \"%s - %u - Exp:%s\"",
             dnswld.fw.iptables_path, dnswld.fw.chains[i],
             (s_ip >> 24) & 0xFF,
             (s_ip >> 16) & 0xFF,
             (s_ip >> 8) & 0xFF,
             s_ip & 0xFF,
             (d_ip >> 24) & 0xFF,
             (d_ip >> 16) & 0xFF,
             (d_ip >> 8) & 0xFF,
             d_ip & 0xFF,
             action_str,
             FW_RULE_TAG,
             created_at,
             tt_str);

    PUTS_OSYS(LOG_DEBUG, " cmd: [%s]", cmd);
    ret = system(cmd);
    if (ret < 0)
    {
      ret = RET_SYS_ERROR;
      goto EXIT;
    }
  }

  ret = RET_OK;

  EXIT:

  return(ret);
}


/*FUNC+************************************************************************/
/* Function    : del_fw_rule                                                  */
/*                                                                            */
/* Description : Delete rule from iptables for given source and dest.         */
/*                                                                            */
/* Params      : s_ip (IN)                - Source IP.                        */
/*               d_ip (IN)                - Destination IP.                   */
/*               created_at (IN)          - Creation timestamp.               */
/*               expiry (IN)              - Expiry timestamp.                 */
/*                                                                            */
/* Returns     : RET_OK                   - Success otherwise error.          */
/*                                                                            */
/*FUNC-************************************************************************/
int del_fw_rule(unsigned int s_ip, unsigned int d_ip, int action,
                unsigned int created_at, unsigned int expiry)
{
  char cmd[1024];
  char tt_str[31] = {0};
  char *action_str;
  int i;
  int ret;

  action_str = (action == FW_ACCEPT_RULE) ? "ACCEPT" : "DROP";
  ctime_r((time_t *)&expiry, tt_str);
  if (strlen(tt_str))
  {
    tt_str[strlen(tt_str) -1] = '\0';
  }

  /****************************************************************************/
  /* Add the rule for each chain.                                             */
  /****************************************************************************/
  for (i = 0; i < dnswld.fw.n_chains; i++)
  {
    snprintf(cmd, sizeof(cmd),
             "%s -D %s -s %d.%d.%d.%d -d %d.%d.%d.%d -j %s "
             "-m comment --comment \"%s - %u - Exp:%s\"",
             dnswld.fw.iptables_path, dnswld.fw.chains[i],
             (s_ip >> 24) & 0xFF,
             (s_ip >> 16) & 0xFF,
             (s_ip >> 8) & 0xFF,
             s_ip & 0xFF,
             (d_ip >> 24) & 0xFF,
             (d_ip >> 16) & 0xFF,
             (d_ip >> 8) & 0xFF,
             d_ip & 0xFF,
             action_str,
             FW_RULE_TAG,
             created_at,
             tt_str);

    PUTS_OSYS(LOG_DEBUG, " cmd: [%s]", cmd);
    ret = system(cmd);
    if (ret < 0)
    {
      ret = RET_SYS_ERROR;
      goto EXIT;
    }
  }

  ret = RET_OK;

  EXIT:

  return(ret);
}

