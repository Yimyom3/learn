public KernelHandle
public NtHandle
 
.code
KernelHandle proc
	xor rax, rax ;��ʼ��rax�Ĵ���
	mov rax, gs:[60h] ;64λgs�Ĵ����洢TEB�ṹ��ĵ�ַ��TEB + 0x60 = PEB�ṹ��ĵ�ַ
	mov rax, [rax + 18h] ;PEB + 0x18 = PEB_LDR_DATA�ṹ��ĵ�ַ
	mov rax, [rax + 10h] ; PEB_LDR_DATA + 0x10 = InLoadOrderModuleList(Reserved2[1])��Flink�ֶ�, Flink�ֶ�ָ��LDR_DATA_TABLE_ENTRY�ṹ��
	mov rax, [rax] ;������һ������(��һ���ǳ�����)����ȡ��һ�������Flink�ֶ�
	mov rax, [rax] ;�����ڶ�������(�ڶ�����ntdll.dll)����ȡ��һ�������Flink�ֶ�
	mov rax, [rax + 30h] ;LDR_DATA_TABLE_ENTRY + 0x30 = Kernel32.dll�ĵ�ַ
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