public KernelHandle
public NtHandle
public RunCalc

 
.code
KernelHandle proc
	mov rax, gs:[60h] ;64λgs�Ĵ����洢TEB�ṹ��ĵ�ַ��TEB + 0x60 = PEB�ṹ��ĵ�ַ
	mov rax, [rax + 18h] ;PEB + 0x18 = PEB_LDR_DATA�ṹ��ĵ�ַ
	mov rax, [rax + 10h] ; PEB_LDR_DATA + 0x10 = InLoadOrderModuleList(Reserved2[1])��Flink�ֶ�, Flink�ֶ�ָ��LDR_DATA_TABLE_ENTRY�ṹ��
	mov rax, [rax] ;������һ������(��һ���ǳ�����)����ȡ��һ�������Flink�ֶ�
	mov rax, [rax] ;�����ڶ�������(�ڶ�����ntdll.dll)����ȡ��һ�������Flink�ֶ�
	mov rax, [rax + 30h] ;LDR_DATA_TABLE_ENTRY + 0x30 = Kernel32.dll�ĵ�ַ
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
    xor rcx, rcx; �����￪ʼ����ѭ��
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
        cmp ecx, dword ptr [rsi + 14h]; ��������
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