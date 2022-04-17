# evbunpack
[Enigma Virtual Box](https://enigmaprotector.com/) unpacker

## Features
Unpacks PE / external external packages made with [Enigma Vitrual Box](https://enigmaprotector.com/)

Supports compressed archives and basically every recent version of EVB (tested 6.x & 9.x)

### Installation
	pip install evbunpack

### Usage

    usage: __main__.py [-h] [--legacy] file output

    Enigma Vitural Box Unpacker

    positional arguments:
      file        File to be unpacked
      output      Extract destination directory

    options:
      -h, --help  show this help message and exit
      --legacy    Enable compatibility mode to work with older (6.x) EVB packages

### Examples
	python -m evbunpack Lycoris_radiata.mys ../biman5_chs_moe
	python -m evbunpack biman2.exe extract --legacy
## TODO
- Depack original PEs
- Restore file timestamps
- Registery configuration extraction

## Credits
[evb-extractor](https://github.com/EVBExtractor/evb-extractor)

[aplib](https://github.com/snemes/aplib)

## License
Apache 2.0 License
