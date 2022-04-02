#include "nemu.h"
#include "monitor/monitor.h"
#include "monitor/watchpoint.h"

/* The assembly code of instructions executed is only output to the screen
 * when the number of instructions executed is less than this value.
 * This is useful when you use the `si' command.
 * You can modify this value as you want.
 */
#define MAX_INSTR_TO_PRINT 10

int nemu_state = NEMU_STOP;

void exec_wrapper(bool);

extern int* scan_watchpoint(); 

/* Simulate how the CPU works. */
void cpu_exec(uint64_t n) {
  if (nemu_state == NEMU_END) {
    printf("Program execution has ended. To restart the program, exit NEMU and run again.\n");
    return;
  }
  nemu_state = NEMU_RUNNING;

  //bool print_flag = n < MAX_INSTR_TO_PRINT;
  bool print_flag;
  int i = 0;

  for (; n > 0; n --) {
    /* Execute one instruction, including instruction fetch,
     * instruction decode, and the actual execution. */
    i++;
    print_flag = i < MAX_INSTR_TO_PRINT;

    exec_wrapper(print_flag);
#ifdef DEBUG
    /* TODO: check watchpoints here. */
    int* no = scan_watchpoint();
    if(*no != -1){
        int i;
        for(i=0; *(no+i)!=-1; i++){
          printf("NO.%d ", *(no + i));
        }
        printf("watchpoint has been changed\n");
        nemu_state = NEMU_STOP;
    }
#endif

#ifdef HAS_IOE
    extern void device_update();
    device_update();
#endif

    if (nemu_state != NEMU_RUNNING) { return; }
  }

  if (nemu_state == NEMU_RUNNING) { nemu_state = NEMU_STOP; }
}
