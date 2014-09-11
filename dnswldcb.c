/*FILE+************************************************************************/
/* Filename    : dnswldcb.c                                                   */
/*                                                                            */
/* Description : DNS Whitelist daemon control block definition.               */
/*                                                                            */
/* Revisions   : 05/10/14  Sho                                                */
/*                         - Creation.                                        */
/*                                                                            */
/*FILE-************************************************************************/

#include <common.h>
#include <dnswldcb.h>


/******************************************************************************/
/* Main control block                                                         */
/******************************************************************************/
dnswld_cb dnswld;
char prog_name[PROC_NAME_MAX_LEN] = {0};


/*FUNC+************************************************************************/
/* Function    : init_dnswld                                                  */
/*                                                                            */
/* Description : Set default settings/values.                                 */
/*                                                                            */
/* Params      : none                                                         */
/*                                                                            */
/* Returns     : none                                                         */
/*                                                                            */
/*FUNC-************************************************************************/
void init_dnswld(void)
{
  memset(&dnswld, 0, sizeof(dnswld));

  /****************************************************************************/
  /* Process defaults.                                                        */
  /****************************************************************************/
  dnswld.proc.is_daemon = TRUE;
  dnswld.proc.is_running = TRUE;

  dnswld.proc.wl_age = DEF_WHITELIST_AGE;

  /****************************************************************************/
  /* Configuration file.                                                      */
  /****************************************************************************/
  strcpy(dnswld.proc.config_file, DEF_CONFIG_FILE);

  /****************************************************************************/
  /* Packet buffers.                                                          */
  /****************************************************************************/
  dnswld.proc.pkt_bufz = DNS_PAYLOADZ;

  /****************************************************************************/
  /* Default logging settings.                                                */
  /****************************************************************************/
  dnswld.log.is_debug_on = FALSE;
  dnswld.log.facility = LOG_SYSLOGGER;

  /****************************************************************************/
  /* Default FW chains.                                                       */
  /****************************************************************************/
  strcpy(dnswld.fw.chains[0], "FORWARD");
  dnswld.fw.n_chains = 1;
  strcpy(dnswld.fw.iptables_path, "/sbin/iptables");

  /****************************************************************************/
  /* Command channel settings.                                                */
  /****************************************************************************/
  strcpy(dnswld.proc.cmd_ip, DEF_CMD_IP);
  dnswld.proc.cmd_port = DEF_S_CMD_PORT;
}


/*FUNC+************************************************************************/
/* Function    : init_dns_bufs                                                */
/*                                                                            */
/* Description : Allocate DNS processing buffers.                             */
/*                                                                            */
/* Params      : none                                                         */
/*                                                                            */
/* Returns     : RET_OK                   - Success otherwise error.          */
/*                                                                            */
/*FUNC-************************************************************************/
int init_dns_bufs(void)
{
  int ret = RET_OK;

  dnswld.proc.pkt_buf = (char *)malloc(dnswld.proc.pkt_bufz);
  if (!dnswld.proc.pkt_buf)
  {
    PUTS_OSYS(LOG_INFO, "Failed to allocate packet buffer.");
    ret = RET_MEMORY_ERROR;
  }

  return(ret);
}


/*FUNC+************************************************************************/
/* Function    : clean_dns_bufs                                               */
/*                                                                            */
/* Description : Clean-up DNS buffers.                                        */
/*                                                                            */
/* Params      : none                                                         */
/*                                                                            */
/* Returns     : none                                                         */
/*                                                                            */
/*FUNC-************************************************************************/
void clean_dns_bufs(void)
{
  if (dnswld.proc.pkt_buf)
  {
    free(dnswld.proc.pkt_buf);
  }
}


/*FUNC+************************************************************************/
/* Function    : init_data_stores                                             */
/*                                                                            */
/* Description : Initialize data stores.                                      */
/*                                                                            */
/* Params      : none                                                         */
/*                                                                            */
/* Returns     : RET_OK                   - Success otherwise error.          */
/*                                                                            */
/*FUNC-************************************************************************/
int init_data_stores(void)
{
  int ret;

  /****************************************************************************/
  /* Create whitelist name tree root.                                         */
  /****************************************************************************/
  ret = create_name_tree(&dnswld.ds.whitelist);
  if (ret)
  {
    return(ret);
  }

  /****************************************************************************/
  /* Create blacklist name tree root.                                         */
  /****************************************************************************/
  ret = create_name_tree(&dnswld.ds.blacklist);

  return(RET_OK);
}


/*FUNC+************************************************************************/
/* Function    : clean_ds_stores p                                            */
/*                                                                            */
/* Description : Clean-up data stores.                                        */
/*                                                                            */
/* Params      : none                                                         */
/*                                                                            */
/* Returns     : none                                                         */
/*                                                                            */
/*FUNC-************************************************************************/
void clean_ds_stores(void)
{
  if (dnswld.ds.whitelist)
  {
    destroy_name_tree(&dnswld.ds.whitelist);
  }

  if (dnswld.ds.blacklist)
  {
    destroy_name_tree(&dnswld.ds.blacklist);
  }
}

