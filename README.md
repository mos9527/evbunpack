# evbunpack
[Enigma Vitrual Box](https://enigmaprotector.com/) 外部封包解包工具

## 说明
本工具适用于 [Enigma Vitrual Box](https://enigmaprotector.com/) 的外部包装解包

### 用法
	evbunpack.py [input] [output]

### 示例
	evbunpack.py Lycoris_radiata.mys ../biman5_chs_moe

### 注意
- 带`%`的文件夹名不会被更改
- 不支持解包时解压封包
- 不支持注册表项解包
- PE (exe) 封包不能直接解包,但可以通过提取 `.engima1` `.enigma2` 资源并手动截取、合并自制封包后解包
- - PE解包请参见 [evb-extractor](https://github.com/EVBExtractor/evb-extractor)
## TODO
- 增加注册表解包

## Credits
[evb-extractor](https://github.com/EVBExtractor/evb-extractor) (Python 3 fork:[evb-extractor](https://github.com/greats3an/evb-extractor))

## License
Apache License