#include "monitor/watchpoint.h"
#include "monitor/expr.h"

#define NR_WP 32

static WP wp_pool[NR_WP];
static WP *head, *free_;

void init_wp_pool() {
  int i;
  for (i = 0; i < NR_WP; i ++) {
    wp_pool[i].NO = i;
    wp_pool[i].next = &wp_pool[i + 1];
  }
  wp_pool[NR_WP - 1].next = NULL;

  head = NULL;
  free_ = wp_pool;
}

/* TODO: Implement the functionality of watchpoint */

WP *new_wp(){
    if(free_ == NULL){
        assert(0);
    }
    //unlink
    WP *temp = free_;
    free_ = free_->next;
    //insert
    temp->next = NULL;
    return temp;
}

void free_wp(WP* wp){
    wp->exp[0] = '\0';
    wp->new_val = -1;
    wp->next = free_;
    free_ = wp;
    return;
}

extern uint32_t expr(char *e, bool *success);

void set_watchpoint(char *args){
    bool flag = true;
  uint32_t val = expr(args, &flag);

  if (!flag) {
    printf("You input an invalid expression, failed to create watchpoint!");
    return ;
  }  

  WP *wp = new_wp();
  wp->old_val = val;
  memcpy(wp->exp, args, 30);

  if (head == NULL) {
    wp->NO = 1;
    head = wp;
  }
  else {
    WP *wwp;
    wwp = head;
    while (wwp->next != NULL) {
      wwp = wwp->next;
    }
    wp->NO = wwp->NO + 1;
    wwp->next = wp;
  }
  return ;
}

bool delete_watchpoint(int NO){
  if (head == NULL) {
    printf("There is no watchpoint to delete!");
    return false;
  }

  WP *wp;
  if (head->NO == NO) {
    wp = head;
    head = head->next;
    free_wp(wp);
  }
  else {
    wp = head;
    while (wp->next != NULL && wp->next->NO != NO) {
      wp = wp->next;
    }
    if (wp == NULL) {
      printf("Failed to find the NO.%d watchpoint!", NO);
    }
    else {
      WP *del_wp;
      del_wp = wp->next;
      wp->next = del_wp->next;
      free_wp(del_wp);
      printf("NO.%d  watchpoint has been deleted!\n", NO);
    }
  }

  return true;
}

void list_watchpoint(){
    WP *head2 = head;
    if(head == NULL) {
        printf("No watch pint to delete\n");
        return;
    }
    printf("NO Expr               Old Value               New Value\n");
    while(head2){
        printf("%d  %-18s %#x               %#x\n",head2->NO,head2->exp,head2->old_val,head2->new_val);
        head2 = head2->next;
    }
    return;
}
//scan the watch point on every command
int* scan_watchpoint(){
    WP *head2 = head;
    bool success = false;
    static int no[NR_WP];
    int i = 0;

    while(head2){
        head2->new_val = expr(head2->exp,&success);
        if(head2->new_val != head2->old_val){
            no[i++] = head2->NO;
            head2->old_val = head2->new_val;
        }
        head2 = head2->next;
    }
    no[i] = -1;
    return no;
}
