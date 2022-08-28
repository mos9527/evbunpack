# evbunpack
[Enigma Virtual Box](https://enigmaprotector.com/) unpacker

## Features
- Restores PEs
  - PEs with overlays can be recovered as well (EVB sometimes break them).
  - TLS, Exceptions, and Import Tables are recovered in a way that resembles the original PE most closely.
  - Produces nearly byte-perfect packages. You should be able to run like they were intended to!
- Unpacks EVB's virtual file system w/wo compression (aplib)    
  - This applies to both built-in content and external packages
- Support for older/6.X and newest/9.X EVB packages
## Installation

  **For Windows Users** : Builds are available [here](https://github.com/mos9527/evbunpack/releases)
  
  Or get the latest version from PyPi:
  
      pip install evbunpack

## Usage

    usage: evbunpack [-h] [--ignore-fs] [--ignore-pe IGNORE_PE] [--legacy] [--list] file output

    Enigma Virtual Box Unpacker

    positional arguments:
      file                  File to be unpacked
      output                Extract destination directory

    options:
      -h, --help            show this help message and exit
      --ignore-fs           Don't extract virtual filesystem. Useful if you want the PE only
      --ignore-pe IGNORE_PE
                            Treat PE files like external packages and thereby does not recover the original executable (for usage without pefile)
      --legacy              Enable compatibility mode to work with older (6.x) EVB packages
      --list                Don't extract the files and print the TOC only (surpresses other output)

### Examples
	evbunpack Lycoris_radiata.mys ../biman5_chs_moe
	evbunpack biman2.exe ./extract --legacy
## TODO
- ~~Restore original PEs~~
- Registery configuration extraction

## Credits
[evb-extractor](https://github.com/EVBExtractor/evb-extractor)

[aplib](https://github.com/snemes/aplib)

## License
Apache 2.0 License
