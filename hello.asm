sub rsp,38
mov dword ptr ss:[rsp+34],0
mov ecx,FFFFFFF5
call qword ptr ds:[<&GetStdHandle>]
mov qword ptr ss:[rsp+28],rax
mov rcx,qword ptr ss:[rsp+28]
lea rdx,qword ptr ds:[<"Hello world!\r\n">]
mov r8d,D
lea r9,qword ptr ss:[rsp+30]
xor eax,eax
mov qword ptr ss:[rsp+20],0
call qword ptr ds:[<&WriteFile>]
xor ecx,ecx
call qword ptr ds:[<&ExitProcess>]
