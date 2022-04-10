# UEFI Helper
[![License: GPL v3](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](http://www.gnu.org/licenses/gpl-3.0)
## Description 
**UEFI Helper** 

+ A tool base on IDA python to help find GetVariable Service and its Variable in UEFI firmware. 
+ The tools is used as preprocessing for UEFI NVRAM fuzz ([efi_fuzz](https://github.com/Sentinel-One/efi_fuzz))

## Usage 


**Notice**

+ Change the config.json file before using the code

`pip3 install requirement.txt`

```python
Usage: python3 main.py [OPTIONS]
Options:
  -w, --max_workers INTEGER  Number of workers
  -b, --binary TEXT          path of UEFI firmware
  --help                     Show this message and exit.
```


**Result**

+ PE files in the firmware will be stored in modules
+ Analyse result will be stored in helper/logs and result.txt



## References

+ https://github.com/binarly-io/efiXplorer
+ https://github.com/yeggor/UEFI_RETool
+ https://github.com/snare/ida-efiutils