#include "monitor/watchpoint.h"
#include "nemu.h"
#include <stdlib.h>
#include <readline/readline.h>
#include <readline/history.h>

void cpu_exec(uint64_t);

/* We use the `readline' library to provide more flexibility to read from stdin. */
char* rl_gets() {
  static char *line_read = NULL;

  if (line_read) {
    free(line_read);
    line_read = NULL;
  }

  line_read = readline("(nemu) ");

  if (line_read && *line_read) {
    add_history(line_read);
  }

  return line_read;
}

static int cmd_c(char *args) {
  cpu_exec(-1);
  return 0;
}

static int cmd_q(char *args) {
  return -1;
}

static int cmd_si(char *args){
  /* get args_str to uint64*/
  
  if(args == NULL){
      cpu_exec(1);     
  }
  else{
      char *n_str = strtok(args, " ");
      uint64_t n = atoll(n_str);
      /*
      while(n--){
          cpu_exec(1);
      }
      */
      cpu_exec(n);

  }
  return 0;
}
extern void list_watchpoint();
static int cmd_info(char *args){
    if(args == NULL) {printf("Please input argument\n"); return 0;}
    else{
        //split string
        char *n_str = strtok(args, " ");
        if(!strcmp(n_str,"r")){
            //print all regeister
            for(int i=0; i<8; i++){
                printf("%s:\t%#010x\t", regsl[i], cpu.gpr[i]._32);
                printf("\n");
            }
        }
        else if(!strcmp(n_str,"w")){
            list_watchpoint();
        }
    }
    return 0;
}

static int cmd_x(char *args){
    if(args == NULL){printf("Please input argument\n"); return 0;}
    else{
        printf("%-10s\t%-10s\t%-10s\n","Address","DwordBlock","DwordBlock");
        char *n_str = strtok(args, " ");
        if(!memcmp(n_str,"0x",2)){
           long addr = strtol(n_str,NULL,16);
           printf("%#010x\t",(uint32_t)addr);
           printf("%#010x\n",vaddr_read(addr,4)); 
        }
        else{
            int n = atoi(n_str);
            n_str = strtok(NULL, " ");
            long addr = strtol(n_str,NULL, 16);
            while(n){
                printf("%#010x\t",(uint32_t)addr);
                for(int i=1; i<=2; i++){
                    printf("%#010x\t",vaddr_read(addr,4));
                    addr += 4;
                    n--;
                    if(n == 0) break;
                }
                printf("\n");
            }
        }
    }
    return 0;
}

extern uint32_t expr(char *e, bool *success);

static int cmd_p(char *args){
    if(args == NULL){printf("Please input argument\n"); return 0;}
    else{
        bool success = false;
        uint32_t result = expr(args, &success);
        if(!success){
            printf("Wrong express!\n");
            return 0;
        }
        else{
            printf("%#x\n",result);
        }
    }
    return 0;

}

static int cmd_set(char *args){
  paddr_t dest_addr;
  uint32_t data;
  bool success = false;


  if(args == NULL) {
    printf("Please input argument\n");
    return 0;
  }
  else{
    //split string
    char *dest_addr_str = strtok(args, " ");
    char *data_str = strtok(NULL, " ");
    if( (dest_addr_str==NULL) || (data_str == NULL)){
      printf("wrong argument\n");
      return 0;
    }
    dest_addr = expr(dest_addr_str, &success);
    if(!success) {
      printf("Wrong express!\n");
      return 0;
    }
    data = expr(data_str, &success);
    if(!success) {
      printf("Wrong express!\n");
      return 0;
    }
    vaddr_write(dest_addr, 4, data);
    return 0;
  }
}


extern int set_watchpoint(char *e);
extern bool delete_watchpoint(int NO);
//set the watch point
static int cmd_w(char *args){
    if(args == NULL){
        printf("Please input argument\n");
        return 0;
    }
    else{
  
        set_watchpoint(args);
        return 0;
    }
}

static int cmd_d(char *args){
    if(args == NULL){
        printf("Please input argument\n");
        return 0;
    }
    else{
        int n = atoi(args);
        if(delete_watchpoint(n)){
            printf("delete %d watchpoint success\n",n);
        }
        else{
            printf("Not found\n");
        }
        return 0;
    }
}

static int cmd_help(char *args);

static struct {
  char *name;
  char *description;
  int (*handler) (char *);
} cmd_table [] = {
  { "help", "Display informations about all supported commands", cmd_help },
  { "c", "Continue the execution of the program", cmd_c },
  { "q", "Exit NEMU", cmd_q },
  { "si", "Execute the step by one", cmd_si},

  /* TODO: Add more commands */
  { "info", "Show all the regester' information", cmd_info },
  { "x", "Show the memory things", cmd_x },
  { "p", "Show varibeals and numbers", cmd_p },
  { "w", "Set the watch point", cmd_w },
  { "d", "Delete the watch point", cmd_d },
  {"set", "Set memory", cmd_set}
};

#define NR_CMD (sizeof(cmd_table) / sizeof(cmd_table[0]))

static int cmd_help(char *args) {
  /* extract the first argument */
  char *arg = strtok(NULL, " ");
  int i;

  if (arg == NULL) {
    /* no argument given */
    for (i = 0; i < NR_CMD; i ++) {
      printf("%s - %s\n", cmd_table[i].name, cmd_table[i].description);
    }
  }
  else {
    for (i = 0; i < NR_CMD; i ++) {
      if (strcmp(arg, cmd_table[i].name) == 0) {
        printf("%s - %s\n", cmd_table[i].name, cmd_table[i].description);
        return 0;
      }
    }
    printf("Unknown command '%s'\n", arg);
  }
  return 0;
}

void ui_mainloop(int is_batch_mode) {
  if (is_batch_mode) {
    cmd_c(NULL);
    return;
  }

  while (1) {
    char *str = rl_gets();
    char *str_end = str + strlen(str);

    /* extract the first token as the command */
    char *cmd = strtok(str, " ");
    if (cmd == NULL) { continue; }

    /* treat the remaining string as the arguments,
     * which may need further parsing
     */
    char *args = cmd + strlen(cmd) + 1;
    if (args >= str_end) {
      args = NULL;
    }

#ifdef HAS_IOE
    extern void sdl_clear_event_queue(void);
    sdl_clear_event_queue();
#endif

    int i;
    for (i = 0; i < NR_CMD; i ++) {
      if (strcmp(cmd, cmd_table[i].name) == 0) {
        if (cmd_table[i].handler(args) < 0) { return; }
        break;
      }
    }

    if (i == NR_CMD) { printf("Unknown command '%s'\n", cmd); }
  }
}
