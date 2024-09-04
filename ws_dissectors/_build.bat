setlocal

call %1\VC\Auxiliary\Build\vcvarsall.bat x86_amd64

msbuild /m:8 /p:Configuration=Release build_win64\Wireshark.sln