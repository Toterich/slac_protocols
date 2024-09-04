# SLAC Protocols

This project contains Wireshark dissectors for some of the binary protocols defined by Stanford's SLAC National Accelerator Laboratory (see https://confluence.slac.stanford.edu/display/ppareg/SLAC+Protocols).
It contains dissectors for

* The Reliable SLAC Streaming Protocol (RSSI): https://confluence.slac.stanford.edu/pages/viewpage.action?pageId=211782868
* The AxiStream Packetizer Protocol Version 2: https://confluence.slac.stanford.edu/display/ppareg/AxiStreamPacketizer+Protocol+Version+2

Specifically, this is intended to analyze AxiStream packets that are transported on top of the RSSI protocol, meaning that the RSSI dissector hands off its payload to the AxiStream dissector automatically.

## Cloning the Repo

This repository includes Wireshark as a git submodule. In order to check out everything, add `--recurse-submodules` to your `clone` command, such as

```bash
git clone <URL OF THIS REPOSITORY> --recurse-submodules
```

## Using the dissectors

Precompiled dlls of the protocol dissectors for use with some versions of Wireshark are present in the `lib\` directory. These are compiled for Windows 11 64bit.

If you use this version of Windows and one of the Wireshark versions present in the `lib\` directory, you may just copy the dlls to the following folder in your Wireshark installation directory, e.g.:

`plugins\4.0\epan\`

If you're on another target or want to modify and recompile the dissectors yourself, see below.

## Compilation

This project can only be built on Windows 10/11 at this time.

### Dependencies

In order to build wireshark, the following dependencies need to be met:

* Visual Studio 2022
* Python3
* Flex
  * This can be installed with chocolatey, via `choco install winflexbison3`

### Build

Copy the file `build_params.bat.template` to `build_params.bat` and modify it to match your local installation. Then, just execute `configure_and_build.bat`.
The script will trigger the compilation of Wireshark along with the dissector plugins. Unfortunately, the plugin architecture of Wireshark is such that the whole application needs to be built in order to create some plugin DLLs, so the build process may take some time.

NOTE: For configuring the build process, a symbolic link needs to be created inside the wireshark subdirectory. This requires either Administrator priviliges or the Windows Developer mode to be active.

After the build process finishes, the plugin dlls can be found in the build directory, e.g. for a build with Wireshark 4.0, in `build_win64\run\Release\plugins\4.0\epan`.

### Using another Wireshark Version

If you want to compile the dissectors for another Wireshark version, you need to change the included Wireshark source code (under `wireshark`) to the minor version number of your installation. As the Wireshark repository is included here as a git submodule, this can easily be done by checking out the corresponding tag in the submodule prior to building.
