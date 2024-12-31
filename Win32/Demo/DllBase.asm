public KernelHandle
public NtHandle
 
.code
KernelHandle proc
	xor rax, rax ;初始化rax寄存器
	mov rax, gs:[60h] ;64位gs寄存器存储TEB结构体的地址，TEB + 0x60 = PEB结构体的地址
	mov rax, [rax + 18h] ;PEB + 0x18 = PEB_LDR_DATA结构体的地址
	mov rax, [rax + 10h] ; PEB_LDR_DATA + 0x10 = InLoadOrderModuleList(Reserved2[1])的Flink字段, Flink字段指向LDR_DATA_TABLE_ENTRY结构体
	mov rax, [rax] ;跳过第一个链表(第一个是程序本身)，获取下一个链表的Flink字段
	mov rax, [rax] ;跳过第二个链表(第二个是ntdll.dll)，获取下一个链表的Flink字段
	mov rax, [rax + 30h] ;LDR_DATA_TABLE_ENTRY + 0x30 = Kernel32.dll的地址
	ret
KernelHandle endp

NtHandle proc
	xor rax, rax 
	mov rax, gs:[60h] 
	mov rax, [rax + 18h] 
	mov rax, [rax + 10h] 
	mov rax, [rax]
	mov rax, [rax + 30h] 
	ret
NtHandle endp

end