# evbunpack
[Enigma Virtual Box](https://enigmaprotector.com/) unpacker

## Features
- Executable unpacking
  - TLS, Exceptions, Import Tables and Relocs are recovered
  - Executables with [Overlays](https://davidghughes.com/2023/08/06/overlays/) can be restored as well
  - Enigma loader DLLs and extra data added by the packer is stripped
- Virtual Box Files unpacking
  - Supports both built-in files and external packages
  - Supports compressed mode

# Tested Versions
| Packer Version | Notes | Unpack with Flags |
| - | - | - |
| 10.70 | Automatically tested in CI for x86/x64 binaries.  | None |
| 9.60 | Limited testing. | `--legacy-pe` |
| 7.80 | Automatically tested in CI for x86/x64 binaries | `--legacy-fs --legacy-pe` |

## Installation
  **For Windows Users** : Builds are available [here](https://github.com/mos9527/evbunpack/releases)

  Or get the latest version from PyPi:
  ```bash
      pip install evbunpack
  ```

## Usage

    usage: evbunpack [-h] [--log-level {DEBUG,INFO,WARNING,ERROR,CRITICAL}] [-l] [--ignore-fs] [--ignore-pe] [--legacy-fs] [--legacy-pe]  [--out-dir OUT_DIR] [--out-pe OUT_PE] file

    Enigma Virtual Box Unpacker

    options:
      -h, --help            show this help message and exit
      --log-level {DEBUG,INFO,WARNING,ERROR,CRITICAL}
                            Set log level

    Flags:
      -l, --list            Don't extract the files and print the table of content to stderr only
      --ignore-fs           Don't extract virtual filesystem
      --ignore-pe           Don't restore the executable
      --legacy-fs           Use legacy mode for filesystem extraction
      --legacy-pe           Use legacy mode for PE restoration

    Output:
      --out-dir OUT_DIR     Output folder
      --out-pe OUT_PE       (If the executable is to be recovered) Where the unpacked EXE is saved. Leave as-is to save it in the output folder.   

    Input:
      file                  File to be unpacked

## Credits
- [evb-extractor](https://github.com/EVBExtractor/evb-extractor)
- [aplib](https://github.com/snemes/aplib)

## License
Apache 2.0 License
