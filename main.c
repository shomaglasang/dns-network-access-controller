/*FILE+************************************************************************/
/* Filename    : main.c                                                       */
/*                                                                            */
/* Description : Entry point of DNS Whitelist daemon program.                 */
/*                                                                            */
/* Revisions   : 05/10/14  Sho                                                */
/*                         - Creation.                                        */
/*                                                                            */
/*FILE-************************************************************************/

#include <common.h>
#include <dnswldcb.h>
#include <config.h>
#include <network.h>


/*FUNC+************************************************************************/
/* Function    : sig_handler                                                  */
/*                                                                            */
/* Description : Program signal handler.                                      */
/*                                                                            */
/* Params      : sig                      - Signal                            */
/*                                                                            */
/* Returns     : none                                                         */
/*                                                                            */
/*FUNC-************************************************************************/
static void sig_handler(int sig)
{
  switch (sig)
  {
    case SIGINT:
    case SIGTERM:
    case SIGHUP:
      dnswld.proc.is_running = FALSE;
      break;
  }
}


/*FUNC+************************************************************************/
/* Function    : daemonize                                                    */
/*                                                                            */
/* Description : Daemonize process.                                           */
/*                                                                            */
/* Params      : none                                                         */
/*                                                                            */
/* Returns     : RET_OK                   - Success otherwise error           */
/*                                                                            */
/*FUNC-************************************************************************/
static int daemonize(void)
{
  int fd;
  int ret;

  ret = fork();
  if (ret == -1)
  {
    return (RET_FORK_ERROR);
  }
  else if (ret == 0)
  {
    fd = open("/dev/null", O_RDWR);
    dup2(fd, STDIN_FILENO);
    dup2(fd, STDOUT_FILENO);
    dup2(fd, STDERR_FILENO);
    close(fd);
  }
  else
  {
    _exit(0);
  }

  return(RET_OK);
}


/*FUNC+************************************************************************/
/* Function    : main                                                         */
/*                                                                            */
/* Description : Program's entry point.                                       */
/*                                                                            */
/* Params      : argc                     - Number of command line args.      */
/*               argv                     - Arguments array.                  */
/*                                                                            */
/* Returns     : RET_OK                   - Success.                          */
/*               RET_GEN_ERR              - Error.                            */
/*                                                                            */
/*FUNC-************************************************************************/
int main(int argc, char **argv)
{
  struct sigaction sig_act;
  fd_set r_fdset;
  int nfds;
  int ret;

  strncpy(prog_name, argv[0], sizeof(prog_name) - 1);

  PUTS_OSYS(LOG_DEBUG, "Starting %s", prog_name);

  /****************************************************************************/
  /* Init global control block.                                               */
  /****************************************************************************/
  init_dnswld();

  /****************************************************************************/
  /* Parse command line parameters.                                           */
  /****************************************************************************/
  ret = parse_args(argc, argv);
  if (ret)
  {
    PUTS_OSYS(LOG_INFO, "Error parsing command line args.");
    goto EXIT;
  }

  /****************************************************************************/
  /* Initialize data stores.                                                  */
  /****************************************************************************/
  init_data_stores();

  /****************************************************************************/
  /* Process config file.                                                     */
  /****************************************************************************/
  ret = process_config();
  if (ret)
  {
    PUTS_OSYS(LOG_INFO, "Error processing config file: [%s].",
              dnswld.proc.config_file);
    goto EXIT;
  }

  /****************************************************************************/
  /* Initialize DNS packet buffer.                                            */
  /****************************************************************************/
  ret = init_dns_bufs();
  if (ret)
  {
    PUTS_OSYS(LOG_INFO, "Error initializing DNS buffers.");
    goto EXIT;
  }

  /****************************************************************************/
  /* Create listeners.                                                        */
  /****************************************************************************/
  ret = create_listeners();
  if (ret)
  {
    goto EXIT;
  }

  /****************************************************************************/
  /* Create command channel listener.                                         */
  /****************************************************************************/
  if (!dnswld.proc.disable_cmd_channel)
  {
    ret = create_cmd_listener();
    if (ret)
    {
      goto EXIT;
    }
  }

  /****************************************************************************/
  /* Daemonize if enabled.                                                    */
  /****************************************************************************/
  if (dnswld.proc.is_daemon)
  {
    if (daemonize())
    {
      PUTS_OSYS(LOG_INFO, "Failed to daemonize process.");
      goto EXIT;
    }
  }

  /****************************************************************************/
  /* Setup signal handlers.                                                   */
  /****************************************************************************/
  sig_act.sa_handler = sig_handler;
  sig_act.sa_flags = 0;
  sigemptyset(&sig_act.sa_mask);
  sigaction(SIGINT, &sig_act, NULL);
  sigaction(SIGHUP, &sig_act, NULL);
  sigaction(SIGTERM, &sig_act, NULL);

  /****************************************************************************/
  /* Re-create whitelist from existing firewall rules.                        */
  /****************************************************************************/
  ret = create_whitelist_from_fw_rules();

  /****************************************************************************/
  /* Launch ACL sweeper.                                                      */
  /****************************************************************************/
  ret = create_start_acl_sweeper();
  if (ret)
  {
    PUTS_OSYS(LOG_INFO, "Failed to create and start ACL sweeper thread.");
    goto EXIT;
  }

  /****************************************************************************/
  /* Map listener descriptors.                                                */
  /****************************************************************************/
  nfds = map_listeners_fdset(&r_fdset);

  /****************************************************************************/
  /* Main loop.                                                               */
  /****************************************************************************/
  while (dnswld.proc.is_running)
  {
    check_listeners(&r_fdset, nfds);

    usleep(10);
  }

  EXIT:

  /****************************************************************************/
  /* Clean-up.                                                                */
  /****************************************************************************/
  wait_acl_sweeper();
  clean_src_dest_whitelist();
  clean_listeners();
  clean_dns_bufs();
  clean_ds_stores();

  PUTS_OSYS(LOG_DEBUG, "Done.");

  return(ret);
}

