#pragma once
#include <mutex>
#include <iostream>
#include <io.h>
#include <stdlib.h>
#include <random>
#include <fcntl.h>
#include <dwmapi.h>
#include <vector>
#include <algorithm>


#pragma comment(lib, "dwmapi.lib")

#include <fstream>
std::mutex v_init_mutex;


extern std::chrono::steady_clock::time_point lastCalled;

void create_console()
{
    if (!AllocConsole())
    {
        return;
    }

    auto lStdHandle = GetStdHandle(STD_OUTPUT_HANDLE);
    auto hConHandle = _open_osfhandle(PtrToUlong(lStdHandle), _O_TEXT);
    auto fp = _fdopen(hConHandle, "w");

    freopen_s(&fp, "CONOUT$", "w", stdout);

    *stdout = *fp;
    setvbuf(stdout, NULL, _IONBF, 0);
}
