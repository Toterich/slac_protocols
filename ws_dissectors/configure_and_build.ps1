$CWD=$PSScriptRoot

. $CWD\build_params.local.ps1

Push-Location $CWD

# Add link to the dissector plugin's source code to wireshark's source tree. This is necessary to allow building the
# plugins with wireshark's build system
Push-Location wireshark
cmd.exe /c mklink /d $CWD\wireshark\dissector_plugins $CWD\src
Pop-Location

cmd.exe /c "_configure.bat $VS_PATH $CWD"
cmd.exe /c "_build.bat $VS_PATH"

Pop-Location
