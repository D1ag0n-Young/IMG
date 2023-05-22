	.file	"test.c"
	.machine ppc
	.section	".text"
	.section	.rodata
	.align 2
.LC0:
	.string	"91b8439ef1ea37a9846cc4dddadf3d713e2e07e0c142adc8edac9fa74eae1d9588abd0e76d466513"
	.section	".text"
	.align 2
	.globl main
	.type	main, @function
main:
.LFB6:
	.cfi_startproc
	stwu 1,-32(1)
	.cfi_def_cfa_offset 32
	mflr 0
	stw 0,36(1)
	stw 31,28(1)
	.cfi_offset 65, 4
	.cfi_offset 31, -4
	mr 31,1
	.cfi_def_cfa_register 31
	lis 9,.LC0@ha
	la 3,.LC0@l(9)
	crxor 6,6,6
	bl printf
	li 9,0
	mr 3,9
	addi 11,31,32
	lwz 0,4(11)
	mtlr 0
	lwz 31,-4(11)
	.cfi_def_cfa 11, 0
	mr 1,11
	.cfi_restore 31
	.cfi_def_cfa_register 1
	blr
	.cfi_endproc
.LFE6:
	.size	main,.-main
	.ident	"GCC: (Ubuntu 10.3.0-1ubuntu1~20.04) 10.3.0"
	.section	.note.GNU-stack,"",@progbits
