/*FILE+************************************************************************/
/* Filename    : data_dict.c                                                  */
/*                                                                            */
/* Description : DNS data dictionary implementation.                          */
/*                                                                            */
/* Revisions   : 05/21/14  Sho                                                */
/*                         - Creation.                                        */
/*                                                                            */
/*FILE-************************************************************************/

#include <common.h>


/*FUNC+************************************************************************/
/* Function    : add_name_to_dictionary                                       */
/*                                                                            */
/* Description : Add DNS name to dictionary.                                  */
/*                                                                            */
/* Params      : name (IN)                - DNS name (dotted format).         */
/*               root (IN/OUT)            - Root of name tree.                */
/*                                                                            */
/* Returns     : RET_OK                   - Success otherwise error.          */
/*                                                                            */
/*FUNC-************************************************************************/
int add_name_to_dictionary(char *name, dnt_node *root)
{
  dnt_node *parent_node;
  dnt_node *new_node;
  dnt_node *prev_node;
  dnt_node *runner;
  char labels[DNS_MAX_NUM_LABELS][DNS_MAX_LABEL_LEN + 1];
  char *label;
  int cmp_ret;
  int n_labels;
  int ret;

  n_labels = dns_name_to_labels(name, labels);
  if (n_labels <= 0)
  {
    ret = RET_GEN_ERROR;
    goto EXIT;
  }

  dump_labels(labels, n_labels);

  n_labels--;
  parent_node = root;

  while (n_labels >= 0)
  {
    label = labels[n_labels];
    PUTS_OSYS(LOG_DEBUG, " label: [%s]", label);

    /**************************************************************************/
    /* Create new node for the label.                                         */
    /**************************************************************************/
    new_node = (dnt_node *)malloc(sizeof(dnt_node));
    if (!new_node)
    {
      PUTS_OSYS(LOG_ERR, "Failed to allocate memory for label.");
      ret = RET_MEMORY_ERROR;
      goto EXIT;
    }

    memset(new_node, 0, sizeof(dnt_node));
    strcpy(new_node->name, label);
    if (!strcmp(label, WILDCARD_NODE_NAME))
    {
      new_node->type = NODE_WILDCARD_TYPE;
    }

    PUTS_OSYS(LOG_DEBUG, "  Parent node: [%s]", parent_node->name);

    if (!parent_node->h_child)
    {
      /************************************************************************/
      /* First node.                                                          */
      /************************************************************************/
      PUTS_OSYS(LOG_DEBUG, "  Adding first child node: [%s]", new_node->name);
      parent_node->h_child = parent_node->t_child = new_node;
      parent_node = new_node;
    }
    else
    {
      /************************************************************************/
      /* Find the position for the new node.                                  */
      /************************************************************************/
      for (runner = parent_node->h_child, prev_node = NULL; runner;
           prev_node = runner, runner = runner->next)
      {
        cmp_ret = strcasecmp(new_node->name, runner->name);
        if (cmp_ret <= 0)
        {
          break;
        }
      }

      if (!cmp_ret)
      {
        PUTS_OSYS(LOG_DEBUG, "  Found existing child node: [%s]",
                  new_node->name);
        parent_node = runner;
      }
      else if (!prev_node)
      {
        PUTS_OSYS(LOG_DEBUG, "  Adding [%s] before [%s]",
                  new_node->name, runner->name);
        new_node->next = runner;
        parent_node->h_child = new_node;
        parent_node = new_node;
      }
      else
      {
        PUTS_OSYS(LOG_DEBUG, "  Adding [%s] after [%s]",
                  new_node->name, prev_node->name);
        new_node->next = prev_node->next;
        prev_node->next = new_node;
        parent_node = new_node;
      }
    }

    n_labels--;
  }

  ret = RET_OK;

  EXIT:

  if (ret)
  {
  }

  return(ret);
}


/*FUNC+************************************************************************/
/* Function    : find_name                                                    */
/*                                                                            */
/* Description : Find DNS name from dictionary.                               */
/*                                                                            */
/* Params      : q (IN)                   - DNS name (question structure)     */
/*               root (IN/OUT)            - Root of name tree.                */
/*                                                                            */
/* Returns     : TRUE                     - Found otherwise FALSE.            */
/*                                                                            */
/*FUNC-************************************************************************/
int find_name(dns_question *q, dnt_node *root)
{
  dnt_node *parent_node;
  dnt_node *runner;
  char *label;
  int cmp_ret;
  int n_labels = q->n_label;
  int ret;

  n_labels--;
  parent_node = root;

  while (n_labels >= 0)
  {
    label = q->labels[n_labels];
    PUTS_OSYS(LOG_DEBUG, " label[%d]: [%s]", n_labels, label);

    for (runner = parent_node->h_child; runner; runner = runner->next)
    {
      PUTS_OSYS(LOG_DEBUG, " runner->name: [%s]", runner->name);
      if (runner->type == NODE_WILDCARD_TYPE)
      {
        PUTS_OSYS(LOG_DEBUG, " wildcard node. matched!");
        goto WILDCARD;
      }

      cmp_ret = strcasecmp(label, runner->name);
      if (cmp_ret == 0)
      {
        parent_node = runner;
        break;
      }
      else if (cmp_ret < 0)
      {
        ret = FALSE;
        goto EXIT;
      }
    }

    if (!runner)
    {
      ret = FALSE;
      goto EXIT;
    }

    n_labels--;
  }

  WILDCARD:

  ret = TRUE;

  EXIT:

  return(ret);
}


/*FUNC+************************************************************************/
/* Function    : create_name_tree                                             */
/*                                                                            */
/* Description : Create and initialize name tree.                             */
/*                                                                            */
/* Params      : root (OUT)               - Name tree root node.              */
/*                                                                            */
/* Returns     : TRUE                     - Found otherwise FALSE.            */
/*                                                                            */
/*FUNC-************************************************************************/
int create_name_tree(dnt_node **root)
{
  dnt_node *node;
  int ret;

  node = (dnt_node *)malloc(sizeof(dnt_node));
  if (!node)
  {
    PUTS_OSYS(LOG_ERR, "Name node malloc error.");
    ret = RET_MEMORY_ERROR;
    goto EXIT;
  }

  memset(node, 0, sizeof(*node));
  strcpy(node->name, ROOT_NODE_NAME);

  *root = node;

  ret = RET_OK;

  EXIT:

  return(ret);
}


/*FUNC+************************************************************************/
/* Function    : destroy_name_tree                                            */
/*                                                                            */
/* Description : Destroy name tree.                                           */
/*                                                                            */
/* Params      : root (OUT)               - Name tree root node.              */
/*                                                                            */
/* Returns     : TRUE                     - Found otherwise FALSE.            */
/*                                                                            */
/*FUNC-************************************************************************/
void destroy_name_tree(dnt_node **root)
{
  if (*root)
  {
    free(*root);
    *root = NULL;
  }
}

