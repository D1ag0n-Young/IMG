#include "nemu.h"

/* We use the POSIX regex functions to process regular expressions.
 * Type 'man regex' for more information about POSIX regex functions.
 */
#include <sys/types.h>
#include <regex.h>

enum {
  TK_NOTYPE = 256, TK_EQ, TK_NQ,

  /* TODO: Add more token types */
  NUM, REG, NEG, TK_AND, TK_OR,NOT, DEREF 
};

static struct rule {
  char *regex;
  int token_type;
} rules[] = {

  /* TODO: Add more rules.
   * Pay attention to the precedence level of different rules.
   */

  {" +", TK_NOTYPE},    // spaces
  {"\\+", '+'},         // plus
  {"==", TK_EQ},         // equal
  {"-", '-'},         //minus
  {"\\*", '*'},         //mult
  {"/", '/'},         //div
  {"0x[0-9A-Fa-f]+|[0-9]+",NUM}, //number
  {"\\$eax|\\$ebx|\\$ecx|\\$ebx|\\$ebp|\\$esp|\\$esi|\\$edi|\\$eip|\\$edx",REG},  //regeisters
  {"\\(",'('},          //left kuo
  {"\\)",')'},           //right kuo
  {"&&", TK_AND},       
  {"\\|\\|", TK_OR},
  {"!=", TK_NQ},
  {"!", NOT}
}; 

#define NR_REGEX (sizeof(rules) / sizeof(rules[0]) )

static regex_t re[NR_REGEX];

/* Rules are used for many times.
 * Therefore we compile them only once before any usage.
 */
void init_regex() {
  int i;
  char error_msg[128];
  int ret;

  for (i = 0; i < NR_REGEX; i ++) {
    ret = regcomp(&re[i], rules[i].regex, REG_EXTENDED);
    if (ret != 0) {
      regerror(ret, &re[i], error_msg, 128);
      panic("regex compilation failed: %s\n%s", error_msg, rules[i].regex);
    }
  }
}

typedef struct token {
  int type;
  char str[32];
} Token;

Token tokens[32];
int nr_token;

static bool make_token(char *e) {
  int position = 0;
  int i;
  regmatch_t pmatch;

  nr_token = 0;

  while (e[position] != '\0') {
    /* Try all rules one by one. */
    for (i = 0; i < NR_REGEX; i ++) {
      if (regexec(&re[i], e + position, 1, &pmatch, 0) == 0 && pmatch.rm_so == 0) {
        char *substr_start = e + position;
        int substr_len = pmatch.rm_eo;

        //Log("match rules[%d] = \"%s\" at position %d with len %d: %.*s",
        //    i, rules[i].regex, position, substr_len, substr_len, substr_start);
        position += substr_len;

        /* TODO: Now a new token is recognized with rules[i]. Add codes
         * to record the token in the array `tokens'. For certain types
         * of tokens, some extra actions should be performed.
         */

        switch (rules[i].token_type) {
            case NUM:
                if(substr_len >= 32){
                    printf("Too long!\n");
                    return false;
                }
                else{
                    tokens[nr_token].type = NUM;
                    for(int i=0; i<substr_len; i++)
                        tokens[nr_token].str[i] = substr_start[i];
                    tokens[nr_token].str[substr_len] = '\0';
                    nr_token++;
                }
                break;
            case TK_NOTYPE:
                break;
            case REG:
                tokens[nr_token].type = REG;
                if(!strncmp(substr_start,"$eax",substr_len))
                    sprintf(tokens[nr_token].str,"%d",cpu.eax);

                if(!strncmp(substr_start,"$edx",substr_len))
                    sprintf(tokens[nr_token].str,"%d",cpu.edx);

                if(!strncmp(substr_start,"$ecx",substr_len))
                    sprintf(tokens[nr_token].str,"%d",cpu.ecx);

                if(!strncmp(substr_start,"$ebx",substr_len))
                    sprintf(tokens[nr_token].str,"%d",cpu.ebx);

                if(!strncmp(substr_start,"$ebp",substr_len))
                    sprintf(tokens[nr_token].str,"%d",cpu.ebp);

                if(!strncmp(substr_start,"$esi",substr_len))
                    sprintf(tokens[nr_token].str,"%d",cpu.esi);

                if(!strncmp(substr_start,"$edi",substr_len))
                    sprintf(tokens[nr_token].str,"%d",cpu.edi);

                if(!strncmp(substr_start,"$esp",substr_len))
                    sprintf(tokens[nr_token].str,"%d",cpu.esp);

                if(!strncmp(substr_start,"$eip",substr_len))
                    sprintf(tokens[nr_token].str,"%d",cpu.eip);
                nr_token++;
                break;
                
            default: tokens[nr_token++].type = rules[i].token_type;
        }

        break;
      }
    }

    if (i == NR_REGEX) {
      printf("no match at position %d\n%s\n%*.s^\n", position, e, position, "");
      return false;
    }
  }

  return true;
}

bool check_parentheses(int p,int q);
uint32_t eval(int p, int q);

int find_priovrity(int op){
    switch(op){
     case '+':
         return 1;
     case '-':
         return 1;
     case '*':
         return 2;
     case '/':
         return 2;
     case TK_EQ:
         return 0;
     case TK_NQ:
         return 0;
     case TK_OR:
         return 0;
     case TK_AND:
         return 0;
     case NEG:
         return 3;
     case DEREF:
         return 3;
     case NOT:
         return 3;
     default:
         return 101;
       
    }
}

int find_dominated_op(int p, int q){
    int min = 100;
    int min_id = -1;
    int num = 0;
    int prio = 100;
    for(int i=p; i<=q; i++){
        if(tokens[i].type == '(')
            num++;
        else if(tokens[i].type == ')')
            num--;
        prio = find_priovrity(tokens[i].type) + num*4;
        if(prio < min){
            min = prio;
            min_id = i; 
        }
    }
    return min_id;
}

uint32_t expr(char *e, bool *success) {
  if (!make_token(e)) {
    *success = false;
    return 0;
  }
  else{
      for(int i=0; i<nr_token; i++){
          if(tokens[i].type == '-' && ( i==0 || tokens[i-1].type == '+'\
                      || tokens[i-1].type == '-' || tokens[i-1].type == '*'\
                      || tokens[i-1].type == TK_EQ || tokens[i-1].type == TK_NQ \
                      || tokens[i-1].type == TK_AND || tokens[i-1].type == TK_OR\
                      || tokens[i-1].type == NOT|| tokens[i-1].type == NEG)){
                tokens[i].type = NEG;
          }
      }
      for(int i=0; i<nr_token; i++){
             if(tokens[i].type == '*' && ( i==0 || tokens[i-1].type == '+'\
                         || tokens[i-1].type == '-' || tokens[i-1].type == '*'\
                         || tokens[i-1].type == TK_EQ || tokens[i-1].type == TK_NQ \
                         || tokens[i-1].type == TK_AND || tokens[i-1].type == TK_OR\
                         || tokens[i-1].type == NOT || tokens[i-1].type == NEG ||tokens[i-1].type == DEREF)){
                tokens[i].type = DEREF;
             }
     }
      *success = true;
      return eval(0,nr_token-1);
  }

}

bool check_parentheses(int p, int q){
    int number = 0;
    if(tokens[p].type == '(' && tokens[q].type == ')'){
        for(int i=p+1; i<q; i++){
             if(tokens[i].type == '(')
                number++;
             else if(tokens[i].type == ')')
                 number--;
             if(number < 0){
                 return false;
             }
         }
    }
    else
        return false;
    if(number == 0)
        return true;
    else
        return false;
}

uint32_t eval(int p, int q){
    if(p > q){
        /*Bad expression */
       // printf("Bad expression\n");
        return 0;
    }
    else if(p == q){
        /*Singel token.
         * for now this token should be a number
         * Return the value of the number
         */
        char *endptr;
        long number = strtol(tokens[p].str,&endptr,0);
        return number;
    }
    else if(check_parentheses(p,q) == true){
        /* The expression is surrounded by a matched pair of parentheses.
        * If that is the case, just throw away the parentheses.
        */
        return eval(p + 1, q - 1);
    }
    else{
        /*We shoule do more things here. */
        int op = find_dominated_op(p,q);
        if(op == -1)
            printf("Wrong op position\n");
        int val1 = eval(p,op - 1);
        int val2 = eval(op+1, q);
        switch (tokens[op].type) {
            case '+': return val1 + val2;
            case '-': return val1 - val2;
            case '*': return val1 * val2;
            case '/': return val1 / val2;
            case TK_EQ: return val1 == val2;
            case TK_NQ: return val1 != val2;
            case TK_OR: return val1 || val2;
            case TK_AND: return val1 && val2;
            case NEG:  return -val2;
            case NOT: return !val2;
            case DEREF: return vaddr_read(val2,4);
            default: assert(0);
        }
    }
}
