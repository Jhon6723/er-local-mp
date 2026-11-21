@echo off
set TOOLCHAIN=C:\tools\llvm-mingw-20261020-msvcrt-x86_64
set CC=%TOOLCHAIN%\bin\x86_64-w64-mingw32-g++
set OUT=..\build
if not exist %OUT% mkdir %OUT%
%CC% -std=c++20 -O2 -shared -Wall -Wextra ^
  src\main.cpp src\log.cpp src\config.cpp src\detour.cpp ^
  src\hooks\hooks.cpp src\hooks\eos_shim.cpp src\hooks\winhttp_shim.cpp src\hooks\ws2_probe.cpp src\transport\transport.cpp src\matchbox\client.cpp ^
  -o %OUT%\er_local_mp.dll -lws2_32 -static
echo built %OUT%\er_local_mp.dll
