@echo off
setlocal

set CWD=%~dp0

call "%CWD%build_params.bat"

pushd "%CWD%"

pushd wireshark

rem Add link to the dissector plugin's source code to wireshark's source tree. This is necessary to allow building the
rem plugins with wireshark's build system
if exist "%CWD%wireshark\dissector_plugins\" (
    echo Skipping creation of symbolic link in wireshark\dissector_plugins as it already exists.
) else (
    mklink /d "%CWD%wireshark\dissector_plugins" "%CWD%ws_dissectors\src"
)

popd

call "%CWD%_configure.bat" %VS_PATH% %CWD%
call "%CWD%_build.bat" %VS_PATH%

rem Remove link into wireshark so the submodule stays clean
if exist "%CWD%wireshark\dissector_plugins\" (
    rmdir "%CWD%wireshark\dissector_plugins\"
)

popd