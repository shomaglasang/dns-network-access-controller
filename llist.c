/*FILE+************************************************************************/
/* Filename    : llist.c                                                      */
/*                                                                            */
/* Description : Linked-list related routines.                                */
/*                                                                            */
/* Revisions   : 05/12/14  Sho                                                */
/*                         - Creation.                                        */
/*                                                                            */
/*FILE-************************************************************************/

#include <stdlib.h>
#include <llist.h>


/*FUNC+************************************************************************/
/* Function    : llist_add                                                    */
/*                                                                            */
/* Description : Add an item to a linked-list.                                */
/*                                                                            */
/* Params      : ll (IN/OUT)              - Linked-list                       */
/*               item (IN)                - Item to put into linked-list      */
/*                                                                            */
/* Returns     : none                                                         */
/*                                                                            */
/*FUNC-************************************************************************/
void llist_add(llist *ll, llitem *item)
{
  if (ll->head)
  {
    ((llitem *)ll->tail)->next = item;
  }
  else
  {
    ll->head = item;
    ll->tail = item;
  }
}


/*FUNC+************************************************************************/
/* Function    : llist_clean                                                  */
/*                                                                            */
/* Description : Clean linked-list.                                           */
/*                                                                            */
/* Params      : ll (IN/OUT)              - Linked-list                       */
/*                                                                            */
/* Returns     : none                                                         */
/*                                                                            */
/*FUNC-************************************************************************/
void llist_clean(llist *ll)
{
  llitem *tmp;
  llitem *runner = (llitem *)ll->head;

  while (runner)
  {
    tmp = runner;
    runner = runner->next;

    free(tmp);
  }
}

