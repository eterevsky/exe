#include <windows.h>

int main() {
    DWORD written;
    HANDLE stdout_handle = GetStdHandle(STD_OUTPUT_HANDLE);

    WriteFile(stdout_handle, "Hello world!\r\n", 14, &written, NULL);

    ExitProcess(0);
    return 0;
}
