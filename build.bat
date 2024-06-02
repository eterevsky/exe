ml64 /c /Fo hello.obj hello.asm

"C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.40.33807\bin\Hostx64\x64\link" /SUBSYSTEM:CONSOLE /OUT:hello_asm.exe /DEBUG:NONE /MERGE:.rdata=.text hello.obj "c:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64\kernel32.Lib"
