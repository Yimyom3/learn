public KernelHandle
public NtHandle
public RunCalc

 
.code
KernelHandle proc
	mov rax, gs:[60h] ;64位gs寄存器存储TEB结构体的地址，TEB + 0x60 = PEB结构体的地址
	mov rax, [rax + 18h] ;PEB + 0x18 = PEB_LDR_DATA结构体的地址
	mov rax, [rax + 10h] ; PEB_LDR_DATA + 0x10 = InLoadOrderModuleList(Reserved2[1])的Flink字段, Flink字段指向LDR_DATA_TABLE_ENTRY结构体
	mov rax, [rax] ;跳过第一个链表(第一个是程序本身)，获取下一个链表的Flink字段
	mov rax, [rax] ;跳过第二个链表(第二个是ntdll.dll)，获取下一个链表的Flink字段
	mov rax, [rax + 30h] ;LDR_DATA_TABLE_ENTRY + 0x30 = Kernel32.dll的地址
	ret
KernelHandle endp

NtHandle proc
	mov rax, gs:[60h] 
	mov rax, [rax + 18h] 
	mov rax, [rax + 10h] 
	mov rax, [rax]
	mov rax, [rax + 30h] 
	ret
NtHandle endp

RunCalc proc
	mov rax, gs:[60h] 
	mov rax, [rax + 18h] 
	mov rax, [rax + 10h] 
	mov rax, [rax]
	mov rax, [rax]
	mov rdi, [rax + 30h] 
    mov edx, dword ptr [rdi + 3ch]
    add rdx, rdi
    mov esi, dword ptr [rdx + 88h]  
    add rsi, rdi
    xor rcx, rcx; 从这里开始进入循环
    find_function :
    mov edx, dword ptr [rsi + 20h]
        add rdx, rdi
        mov eax, dword ptr [rdx + rcx * 4]
        add rax, rdi
        mov r9, 00636578456E6957h
        cmp [rax], r9
        jne not_found
        mov edx, dword ptr [rsi + 24h]
        add rdx, rdi
        mov cx, word ptr[rdx + rcx * 2]
        mov edx, dword ptr [rsi + 1ch]
        add rdx, rdi
        mov edx, dword ptr [rdx + rcx * 4]
        add rdi, rdx
        jmp end_search
        not_found :
    inc rcx
        cmp ecx, dword ptr [rsi + 14h]; 函数数量
        jl find_function
    end_search :
        mov rbx, [rsp]
        sub rsp, 8
        mov dword PTR [rsp],636c6163h 
        mov byte PTR [rsp+4],0 
        mov edx, 1
        lea rcx, [rsp]
        call rdi
        add rsp,8
        mov [rsp],rbx
	    ret
RunCalc endp

end