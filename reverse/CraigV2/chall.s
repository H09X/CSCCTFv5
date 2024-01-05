	.file	"chall.c"
	.text
	.globl	getlen
	.type	getlen, @function
getlen:
.LFB309:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	movq	%rdi, -24(%rbp)
	movl	$0, -4(%rbp)
	jmp	.L2
.L3:
	addl	$1, -4(%rbp)
.L2:
	movl	-4(%rbp), %eax
	movslq	%eax, %rdx
	movq	-24(%rbp), %rax
	addq	%rdx, %rax
	movzbl	(%rax), %eax
	testb	%al, %al
	jne	.L3
	movl	-4(%rbp), %eax
	popq	%rbp
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE309:
	.size	getlen, .-getlen
	.globl	validate
	.type	validate, @function
validate:
.LFB310:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	subq	$4368, %rsp
	movq	%rdi, -4344(%rbp)
	movq	%rsi, -4352(%rbp)
	movq	%rdx, -4360(%rbp)
	leaq	-4224(%rbp), %rdx
	movl	$0, %eax
	movl	$524, %ecx
	movq	%rdx, %rdi
	rep stosq
	movl    $0, -4224(%rbp)
	movl	$1, -4220(%rbp)
	movl	$2, -4216(%rbp)
	movl	$10, -4212(%rbp)
	movl	$19, -4208(%rbp)
	movl	$5, -4204(%rbp)
	movl	$41, -4200(%rbp)
	movl	$0, -4192(%rbp)
	movl	$63, -4188(%rbp)
	movl	$34, -4184(%rbp)
	movl	$45, -4180(%rbp)
	movl	$53, -4176(%rbp)
	movl	$36, -4172(%rbp)
	movl	$59, -4168(%rbp)
	movl	$52, -4164(%rbp)
	movl	$109, -4160(%rbp)
	movl	$124, -4156(%rbp)
	movl	$111, -4152(%rbp)
	movl	$8, -4148(%rbp)
	movl	$52, -4144(%rbp)
	movl	$48, -4140(%rbp)
	movl	$55, -4136(%rbp)
	movl	$44, -4132(%rbp)
	movl	$43, -4128(%rbp)
	movl	$43, -4124(%rbp)
	movl	$38, -4120(%rbp)
	movl	$47, -4116(%rbp)
	call	EVP_MD_CTX_new@PLT
	movq	%rax, -16(%rbp)
	call	EVP_sha256@PLT
	movq	%rax, -24(%rbp)
	cmpq	$0, -16(%rbp)
	jne	.L6
	movl	$0, %eax
	jmp	.L15
.L6:
	movq	-24(%rbp), %rcx
	movq	-16(%rbp), %rax
	movl	$0, %edx
	movq	%rcx, %rsi
	movq	%rax, %rdi
	call	EVP_DigestInit_ex@PLT
	cmpl	$1, %eax
	je	.L8
	movl	$0, %eax
	jmp	.L15
.L8:
	movq	-4344(%rbp), %rax
	movq	%rax, %rdi
	call	strlen@PLT
	movq	%rax, %rdx
	movq	-4344(%rbp), %rcx
	movq	-16(%rbp), %rax
	movq	%rcx, %rsi
	movq	%rax, %rdi
	call	EVP_DigestUpdate@PLT
	cmpl	$1, %eax
	je	.L9
	movq	-16(%rbp), %rax
	movq	%rax, %rdi
	call	EVP_MD_CTX_free@PLT
	movl	$0, %eax
	jmp	.L15
.L9:
	leaq	-4292(%rbp), %rdx
	leaq	-4288(%rbp), %rcx
	movq	-16(%rbp), %rax
	movq	%rcx, %rsi
	movq	%rax, %rdi
	call	EVP_DigestFinal_ex@PLT
	cmpl	$1, %eax
	je	.L10
	movq	-16(%rbp), %rax
	movq	%rax, %rdi
	call	EVP_MD_CTX_free@PLT
	movl	$0, %eax
	jmp	.L15
.L10:
	movq	-16(%rbp), %rax
	movq	%rax, %rdi
	call	EVP_MD_CTX_free@PLT
	movabsq	$-1579856855009041498, %rax
	movabsq	$-4317265538333496602, %rdx
	movq	%rax, -4336(%rbp)
	movq	%rdx, -4328(%rbp)
	movabsq	$3551782715010313895, %rax
	movabsq	$-4283370361391506976, %rdx
	movq	%rax, -4320(%rbp)
	movq	%rdx, -4312(%rbp)
	movl	-4292(%rbp), %eax
	movl	%eax, %edx
	leaq	-4336(%rbp), %rcx
	leaq	-4288(%rbp), %rax
	movq	%rcx, %rsi
	movq	%rax, %rdi
	call	memcmp@PLT
	testl	%eax, %eax
	je	.L11
	movl	$0, %eax
	jmp	.L15
.L11:
	movq	-4352(%rbp), %rax
	movq	%rax, %rdi
	call	getlen
	movl	%eax, -28(%rbp)
	movl	$0, -4(%rbp)
	jmp	.L12
.L13:
	movq	-4344(%rbp), %rax
	movq	%rax, %rdi
	call	getlen
	movl	%eax, %esi
	movl	-4(%rbp), %eax
	cltd
	idivl	%esi
	movl	%edx, %ecx
	movl	%ecx, %eax
	movslq	%eax, %rdx
	movq	-4344(%rbp), %rax
	addq	%rdx, %rax
	movzbl	(%rax), %eax
	movsbl	%al, %eax
	movl	%eax, %edi
	call	toupper@PLT
	movl	%eax, %esi
	movl	-4(%rbp), %eax
	cltq
	movl	-4224(%rbp,%rax,1), %eax
	movl	%eax, %ecx
	movl	-4(%rbp), %eax
	movslq	%eax, %rdx
	movq	-4360(%rbp), %rax
	addq	%rdx, %rax
	xorl	%ecx, %esi
	movl	%esi, %edx
	movb	%dl, (%rax)
	addl	$1, -4(%rbp)
.L12:
	movl	-4(%rbp), %eax
	cmpl	-28(%rbp), %eax
	jl	.L13
	movq	-4352(%rbp), %rdx
	movq	-4360(%rbp), %rax
	movq	%rdx, %rsi
	movq	%rax, %rdi
	call	strcmp@PLT
	testl	%eax, %eax
	jne	.L14
	movl	$1, %eax
	jmp	.L15
.L14:
	movl	$0, %eax
.L15:
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE310:
	.size	validate, .-validate
	.section	.rodata
	.align 8
.LC1:
        .ascii  "Welcome to secret poets society!\000"
.LC2:
        .ascii  "Please enter your credentials to login\000"
.LC3:
        .ascii  "Username:\000"
.LC4:
        .ascii  "%s\000"
.LC5:
        .ascii  "Password:\000"
.LC6:
        .ascii  "Access Granted!\012Welcome Back Craig\000"
.LC7:
        .ascii  "Access Denied!\000"
	.text
	.globl	main
	.type	main, @function
main:
.LFB311:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	subq	$3168, %rsp
	leaq	.LC0(%rip), %rax
	movq	%rax, %rdi
	call	puts@PLT
	leaq	.LC1(%rip), %rax
	movq	%rax, %rdi
	call	puts@PLT
	leaq	.LC2(%rip), %rax
	movq	%rax, %rdi
	call	puts@PLT
	leaq	-1056(%rbp), %rax
	movq	%rax, %rsi
	leaq	.LC3(%rip), %rax
	movq	%rax, %rdi
	movl	$0, %eax
	call	__isoc99_scanf@PLT
	leaq	.LC4(%rip), %rax
	movq	%rax, %rdi
	call	puts@PLT
	leaq	-2112(%rbp), %rax
	movq	%rax, %rsi
	leaq	.LC3(%rip), %rax
	movq	%rax, %rdi
	movl	$0, %eax
	call	__isoc99_scanf@PLT
	leaq	-3168(%rbp), %rdx
	leaq	-2112(%rbp), %rcx
	leaq	-1056(%rbp), %rax
	movq	%rcx, %rsi
	movq	%rax, %rdi
	call	validate
	testl	%eax, %eax
	je	.L17
	leaq	.LC5(%rip), %rax
	movq	%rax, %rdi
	call	puts@PLT
	jmp	.L18
.L17:
	leaq	.LC6(%rip), %rax
	movq	%rax, %rdi
	call	puts@PLT
.L18:
	movl	$0, %eax
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE311:
	.size	main, .-main
	.ident	"GCC: (Debian 13.2.0-4) 13.2.0"
	.section	.note.GNU-stack,"",@progbits
