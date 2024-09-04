setlocal
@ECHO OFF

call %1\VC\Auxiliary\Build\vcvarsall.bat x86_amd64

set WIRESHARK_BASE_DIR=%2
set WIRESHARK_VERSION_EXTRA=-SLAC

if not exist build_win64 mkdir build_win64

pushd build_win64

REM Wireshark's Release Build is producing some minor warnings for some reason
REM Set VCSVERSION_OVERRIDE because the script to determine the actual version produces a weird error in our configuration
REM The drawback is that the compiled Wireshark version will display a wrong version number.
cmake -G "Visual Studio 17 2022" -DBUILD_wireshark=OFF ^
    -DENABLE_WERROR=OFF ^
    -DCUSTOM_PLUGIN_SRC_DIR=%2\wireshark\dissector_plugins ^
    -DVCSVERSION_OVERRIDE=1.0.0 ^
    -A x64 ..\wireshark

popd

@ECHO ON
