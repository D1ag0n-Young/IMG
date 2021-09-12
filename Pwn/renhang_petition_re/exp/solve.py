import idc

start = 0x1040
end = 0x289B
cur_addr = start
while cur_addr <= end:
	if idc.print_insn_mnem(cur_addr) == "xor" and idc.print_operand(cur_addr, 0) == "bl" and idc.print_operand(cur_addr, 1) == "[esi]":
		cur_addr = idc.next_head(cur_addr, end)
		r1 = int(idc.print_operand(cur_addr, 1)[:-1], 16) & 0xFF
		for i in range(15):
			cur_addr = idc.next_head(cur_addr, end)
		r2 = int(idc.print_operand(cur_addr, 1)[:-1], 16) & 0xFF
		cur_addr = idc.next_head(cur_addr, end)
		r3 = int(idc.print_operand(cur_addr, 1)[:-1], 16) & 0xFF
		print(chr(r1 ^ r2 ^ r3), end='')
	cur_addr = idc.next_head(cur_addr, end)