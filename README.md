# evbunpack
[Enigma Vitrual Box](https://enigmaprotector.com/) 解包工具

## 说明
本工具适用于 [Enigma Vitrual Box](https://enigmaprotector.com/) 的外部封包、打包程序解包；支持压缩档解包。

### 安装
	pip install evbunpack
### 用法

	usage: __main__.py [-h] [--legacy] file output

	Enigma Vitural Box 解包工具

	positional arguments:
	file        封包 EXE 或外部封包路径
	output      保存路径

	optional arguments:
	-h, --help  show this help message and exit
	--legacy    启用兼容模式，适用于老版本封包
### 示例
	python -m evbunpack Lycoris_radiata.mys ../biman5_chs_moe
	
## TODO
- 增加注册表解包...?

## Credits
[evb-extractor](https://github.com/EVBExtractor/evb-extractor)
[aplib](https://github.com/snemes/aplib)

## License
Apache License