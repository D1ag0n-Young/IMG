stack = [] 
saves = [] 
def get_insts(): 
    datas = open('lemon.txt', 'r').read().split('\n') 

    insts = {} 
    for ii, x in enumerate(datas): 
        id1, ins = x.split(': ') 
        if id1 != '600': 
            id2 = int(datas[ii + 1].split(': ')[0],10) 
        else:
            id2 = 600 
        id1 = int(id1) 
        insts[id1] = [ins, id2] 

    return insts 
def ret(suc, jmp = None): 
    return suc, jmp 
def run_one(ins:str): 
    global stack, saves 
    if ins.startswith('const'): 
        type1 = ins.split('; ')[1].replace(' ', '') 
        if type1.isdigit(): 
            stack = [int(type1)] + stack 
            return ret(True) 
        else:
            stack = [type1] + stack 
            return ret(True) 
    if ins.startswith('array'): 
        arr_len = int(ins[6:]) 
        stack = [stack[:arr_len]] + stack[arr_len:] 
        return ret(True) 
    if ins.startswith('store'): 
        args = ins.split(' ') 
        x = int(args[1]) 
        y = int(args[2]) 
        while x >= len(saves): 
            saves.append([]) 
        while y >= len(saves[x]): 
            saves[x].append(None) 
        saves[x][y] = stack[0] 
        stack = stack[1:] 
        return ret(True) 
    if ins.startswith('load'): 
        args = ins.split(' ') 
        x = int(args[1]) 
        y = int(args[2]) 
        stack = [saves[x][y]] + stack 
        return ret(True) 
    if ins == 'lt': 
        stack = [stack[0] - stack[1]] + stack[2:]
        return ret(True)

    if ins.startswith('jz'): 
        if stack[0] == 0: 
            jmp_pc = int(ins.split(' ')[1]) 
        else:
            jmp_pc = None 
        return ret(True, jmp_pc) 
    if ins.startswith('jmp'): 
        return ret(True, int(ins.split(' ')[1])) 
    if ins == 'getattr': 
        return ret(True) 
    if ins == 'getitem': 
        stack = [stack[1][stack[0]]] + stack[2:] 
        return ret(True) 
    if ins == 'setitem': 
        stack[1][stack[0]] = stack[2] 
        stack = stack[1:] 
        return ret(True) 
    if ins.startswith('call'): 
        w = int(ins.split(' ')[1]) 
        if stack[w] == 'append': 
            x = stack[0] 
            stack[2].append(x) 
            stack = stack[2:] 
            return ret(True) 
        if 'print' in stack[w]: 
            x = stack[0] 
            print(x) 
            stack = stack[2:] 
            return ret(True) 
    if ins == 'pop': 
        stack = stack[1:] 
        return ret(True) 
    if ins == 'add': 
        stack = [stack[1] + stack[0]] + stack[2:] 
        return ret(True) 
    if ins == 'mod': 
        stack = [stack[1] % stack[0]] + stack[2:] 
        return ret(True) 
    if ins == 'bxor': 
        stack = [stack[1] ^ stack[0]] + stack[2:] 
        return ret(True) 
    if ins == 'mul': 
        stack = [stack[1] * stack[0]] + stack[2:] 
        return ret(True) 
    if ins == 'sub': 
        stack = [stack[1] - stack[0]] + stack[2:] 
        return ret(True) 
    return ret(False) 
insts = get_insts() 
pc = 11 

while pc != 600: 
    x = insts[pc][0] 
    nxt_pc = insts[pc][1] 
    can_run, jmp_pc = run_one(x) 
    if not can_run: 
        print('stack :', stack) 
        print('saves :', saves) 
        print(x)
        exit() 
    if jmp_pc != None: 
        nxt_pc = jmp_pc 
    pc = nxt_pc
