/*FILE+************************************************************************/
/* Filename    : config.c                                                     */
/*                                                                            */
/* Description : Configuration related routines.                              */
/*                                                                            */
/* Revisions   : 05/10/14  Sho                                                */
/*                         - Creation.                                        */
/*                                                                            */
/*FILE-************************************************************************/

#include <common.h>
#include <unistd.h>

#include <ret_codes.h>
#include <dnswldcb.h>
#include <util.h>
#include <config.h>


/*FUNC+************************************************************************/
/* Function    : print_usage                                                  */
/*                                                                            */
/* Description : Print usage and exit.                                        */
/*                                                                            */
/* Params      : none                                                         */
/*                                                                            */
/* Returns     : none                                                         */
/*                                                                            */
/*FUNC-************************************************************************/
static void print_usage(void)
{
  fprintf(stdout, "%s [Options]\n", prog_name);
  fprintf(stdout,"Options:\n");
  fprintf(stdout," -d: Emit debug lines. Verbose\n");
  fprintf(stdout," -D: Foreground mode. Un-daemonize\n");
  fprintf(stdout," -c <config file>: Read config file. Default: /etc/dnswld.cfg\n");
  fprintf(stdout," -w <age>: Whitelist age in seconds. Default 300.\n");
  fprintf(stdout," -F: Disable adding firewall whitelist/allow rules.\n");
  fprintf(stdout," -C: Disable command channel.\n");
  fprintf(stdout," -h: Print this usage.\n");
  fprintf(stdout,"\n");
  exit(0);
}


/*FUNC+************************************************************************/
/* Function    : parse_args                                                   */
/*                                                                            */
/* Description : Parse command line arguments.                                */
/*                                                                            */
/* Params      : argc                     - Number of command line args.      */
/*               argv                     - Arguments array.                  */
/*                                                                            */
/* Returns     : RET_OK                   - Success otherwise error           */
/*                                                                            */
/*FUNC-************************************************************************/
int parse_args(int argc, char **argv)
{
  int opt;
  int ret;

  while ((opt = getopt(argc, argv, "HhCFDdc:w:")) != -1)
  {
    switch (opt)
    {
      case 'D':
        dnswld.proc.is_daemon = FALSE;
        break;

      case 'd':
        dnswld.log.is_debug_on = TRUE;
        break;

      case 'c':
        strncpy(dnswld.proc.config_file, optarg,
                sizeof(dnswld.proc.config_file) - 1);
        break;

      case 'F':
        dnswld.proc.disable_fw = TRUE;
        break;

      case 'C':
        dnswld.proc.disable_cmd_channel = TRUE;
        break;

      case 'w':
        dnswld.proc.wl_age = atoi(optarg);
        break;

      case 'h':
      case 'H':
        print_usage();
        break;

      default:
        PUTS_OSYS(LOG_INFO, "Invalid option: [%c]", opt);
        ret = RET_INVALID_OPTION;
        goto EXIT;
    }
  }

  ret = RET_OK;

  EXIT:

  return(ret);
}


/*FUNC+************************************************************************/
/* Function    : parse_add_whitelist_entries                                  */
/*                                                                            */
/* Description : Parse and add whitelist entries.                             */
/*                                                                            */
/* Params      : entries (IN)             - Space separated list of entries.  */
/*                                                                            */
/* Returns     : RET_OK                   - Success otherwise error           */
/*                                                                            */
/*FUNC-************************************************************************/
static int parse_add_whitelist_entries(char *entries)
{
  char *token;
  char *saveptr;
  int ret;

  for (token = strtok_r(entries, " ", &saveptr); token != NULL;
       token = strtok_r(NULL, " ", &saveptr))
  {
    PUTS_OSYS(LOG_DEBUG, "Adding [%s] to whitelist ...", token);
    ret = add_name_to_dictionary(token, dnswld.ds.whitelist);
  }

  ret = RET_OK;

  return(ret);
}


/*FUNC+************************************************************************/
/* Function    : get_chain                                                    */
/*                                                                            */
/* Description : Get chain and return its pointer.                            */
/*                                                                            */
/* Params      : name (IN)                - Name of chain.                    */
/*                                                                            */
/* Returns     : chain                    - Pointer to chain if found or NULL.*/
/*                                                                            */
/*FUNC-************************************************************************/
static char *get_chain(char *name)
{
  int i;

  for (i = 0; i < dnswld.fw.n_chains; i++)
  {
    if (!strcmp(dnswld.fw.chains[i], name))
    {
      return(dnswld.fw.chains[i]);
    }
  }

  return(NULL);
}


/*FUNC+************************************************************************/
/* Function    : parse_add_chains                                             */
/*                                                                            */
/* Description : Parse and add iptables chains.                               */
/*                                                                            */
/* Params      : entries (IN)             - Space separated list of entries.  */
/*                                                                            */
/* Returns     : RET_OK                   - Success otherwise error           */
/*                                                                            */
/*FUNC-************************************************************************/
static int parse_add_chains(char *entries)
{
  char *token;
  char *saveptr;
  int ret;

  for (token = strtok_r(entries, " ", &saveptr);
       (token != NULL) && (dnswld.fw.n_chains < FW_CHAIN_MAX_NUM);
       token = strtok_r(NULL, " ", &saveptr))
  {
    if (get_chain(token))
    {
      PUTS_OSYS(LOG_DEBUG, "Chain [%s] already added. Skipping.", token);
      continue;
    }

    PUTS_OSYS(LOG_DEBUG, "Adding [%s] to chains list at [%d]...", token,
              dnswld.fw.n_chains);
    strncpy(dnswld.fw.chains[dnswld.fw.n_chains], token, FW_CHAIN_MAX_LEN - 1);
    dnswld.fw.n_chains++;
  }

  ret = RET_OK;

  return(ret);
}


/*FUNC+************************************************************************/
/* Function    : process_config                                               */
/*                                                                            */
/* Description : Process configuration file.                                  */
/*                                                                            */
/* Params      : none                                                         */
/*                                                                            */
/* Returns     : RET_OK                   - Success otherwise error           */
/*                                                                            */
/*FUNC-************************************************************************/
int process_config(void)
{
  FILE *in;
  char line[1024];
  char *ptr;
  char *key;
  int line_num;
  int ret;

  in = fopen(dnswld.proc.config_file, "r");
  if (in == NULL)
  {
    PUTS_OSYS(LOG_INFO, "  Failed to open [%s]", dnswld.proc.config_file);
    ret = RET_FILE_OPEN_ERROR;
    goto EXIT;
  }

  line_num = 0;
  while (TRUE)
  {
    line_num++;
    ptr = fgets(line, sizeof(line), in);
    if (!ptr)
    {
      break;
    }

    ptr = trim_str(ptr);

    if ((!strlen(ptr)) || (is_comment(ptr)))
    {
      continue;
    }

    key = strsep(&ptr, ":");
    if (ptr == NULL)
    {
      PUTS_OSYS(LOG_INFO, "Unrecognized statement at line: [%d]", line_num);
      ret = RET_INVALID_CONFIG;
      goto EXIT;
    }

    key = trim_str(key);
    ptr = trim_str(ptr);

    if ((!key) || (!ptr) || (!strlen(key)) || (!strlen(ptr)))
    {
      PUTS_OSYS(LOG_INFO, "Empty keyword/value at line: [%d]", line_num);
      ret = RET_INVALID_CONFIG;
      goto EXIT;
    }

    if (!strcasecmp(key, CFG_BIND))
    {
    }
    else if (!strcasecmp(key, CFG_WHITELIST))
    {
      ret = parse_add_whitelist_entries(ptr);
    }
    else if (!strcasecmp(key, CFG_CHAINS))
    {
      ret = parse_add_chains(ptr);
    }
    else if (!strcasecmp(key, CFG_IPTABLES_PATH))
    {
      strncpy(dnswld.fw.iptables_path, ptr, FILENAME_MAX_LEN - 1);
    }
    else
    {
      PUTS_OSYS(LOG_INFO, "Invalid keyword at line: [%d]", line_num);
      ret = RET_INVALID_CONFIG;
      goto EXIT;
    }
  }

  ret = RET_OK;

  EXIT:

  if (in)
  {
    fclose(in);
  }

  return(ret);
}

