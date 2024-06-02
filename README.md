<https://github.com/aidansteele/osx-abi-macho-file-format-reference>

## Building a Windows executable from asm

1. Add the directory with Visual Studio command line tools to PATH, for me: `C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.40.33807\bin\Hostx64\x64`

2. Run MASM: `ml64 /c /Fo hello.obj hello.asm`

3. Link: `link /SUBSYSTEM:CONSOLE /ENTRY:main /OUT:hello_asm.exe hello.obj "c:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64\kernel32.Lib"`

4. Run `hello.exe`
