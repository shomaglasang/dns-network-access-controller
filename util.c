/*FILE+************************************************************************/
/* Filename    : util.c                                                       */
/*                                                                            */
/* Description : Utility routines.                                            */
/*                                                                            */
/* Revisions   : 05/10/14  Sho                                                */
/*                         - Creation.                                        */
/*                                                                            */
/*FILE-************************************************************************/

#include <common.h>
#include <ctype.h>


/*FUNC+************************************************************************/
/* Function    : trim_str                                                     */
/*                                                                            */
/* Description : Remove leading and ending whitespace of a string.            */
/*                                                                            */
/* Params      : str (OUT)                - String input.                     */
/*                                                                            */
/* Returns     : string                   - Result                            */
/*                                                                            */
/*FUNC-************************************************************************/
char *trim_str(char *str)
{
  char *ptr;
  int len;

  if ((str == NULL) || !(len = strlen(str)))
  {
    return(NULL);
  }

  for (ptr = &str[len -1 ]; ptr != str; ptr--)
  {
    if (isspace(*ptr))
    {
      *ptr = '\0';
    }
    else
    {
      break;
    }
  }

  for (ptr = str; (*ptr != '\0') && (isspace(*ptr)); ptr++);
  sprintf(str, "%s", ptr);

  return (str);
}


/*FUNC+************************************************************************/
/* Function    : is_comment                                                   */
/*                                                                            */
/* Description : Return true if string starts with a #.                       */
/*                                                                            */
/* Params      : str (IN)                 - String input.                     */
/*                                                                            */
/* Returns     : TRUE                     - String is a comment otherwise     */
/*                                          FALSE                             */
/*                                                                            */
/*FUNC-************************************************************************/
int is_comment(char *str)
{
  if (*str == '#')
  {
    return(TRUE);
  }

  return(FALSE);
}


/*FUNC+************************************************************************/
/* Function    : dns_name_to_labels                                           */
/*                                                                            */
/* Description : Convert DNS name to array of labels.                         */
/*                                                                            */
/* Params      : name (IN)                - DNS name.                         */
/*               labels (OUT)             - Array of labels.                  */
/*                                                                            */
/* Returns     : int                      - Number of labels otherwise 0 on   */
/*                                          error                             */
/*                                                                            */
/*FUNC-************************************************************************/
int dns_name_to_labels(char *name,
                       char labels[DNS_MAX_NUM_LABELS][DNS_MAX_LABEL_LEN + 1])
{
  char *token;
  char *saveptr;
  int i;

  for (token = strtok_r(name, ".", &saveptr), i = 0; token != NULL;
       token = strtok_r(NULL, ".", &saveptr), i++)
  {
    if ((i >= DNS_MAX_NUM_LABELS) ||
        (strlen(token) >= DNS_MAX_LABEL_LEN))
    {
      return(0);
    }

    strcpy((char *)&labels[i][0], token);
  }

  labels[i][0] = '\0';

  return(i);
}


/*FUNC+************************************************************************/
/* Function    : dump_labels                                                  */
/*                                                                            */
/* Description : Dump array of labels.                                        */
/*                                                                            */
/* Params      : labels (IN)              - Array of labels.                  */
/*               n (IN)                   - Number of labels in the array.    */
/*                                                                            */
/* Returns     : none                                                         */
/*                                                                            */
/*FUNC-************************************************************************/
void dump_labels(char labels[DNS_MAX_NUM_LABELS][DNS_MAX_LABEL_LEN + 1], int n)
{
  int i;

  PUTS_OSYS(LOG_DEBUG, "Labels:");
  for (i = 0; i < n; i++)
  {
    PUTS_OSYS(LOG_DEBUG, " label[%d]: [%s]", i, labels[i]);
  }
}

