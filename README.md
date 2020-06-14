# ASNRECON
[![License: Apache](https://img.shields.io/github/license/orlyjamie/asnrecon)](https://img.shields.io/github/license/orlyjamie/asnrecon)

A tool to perform reconaissance using autonomous system number (ASN) lookups combined with SSL cert scanning 📡

![](https://raw.githubusercontent.com/orlyjamie/asnrecon/master/screen.png)

## Usage

```
usage: python asnrecon.py

Select an option:
	[1] Full ASN scan
	[2] Specific IPv4 range scan
```

- Full ASN scan 

Using this option, the script will take a single domain/hostname which it will then perform a lookup against the local ASN database and select a list of IP ranges associated with that ASN.

`Note:` The script can take an input file `main.config` which can be used to prevent scanning specific IP ranges. IP addresses to be avoided should be supplied in a comma delimited format. 

- Specific IPv4 range scan

This option accepts an IP address range `0.0.0.0/0` and attempt to perform SSL connections while printing any identified certs

## Installation
  1. `pip install -r requirements.txt`
  2. `wget https://raw.githubusercontent.com/hadiasghari/pyasn/master/pyasn-utils/pyasn_util_download.py`
  3. `wget https://raw.githubusercontent.com/hadiasghari/pyasn/master/pyasn-utils/pyasn_util_convert.py`
  4. `python pyasn_util_download.py --latest`
  5. `python pyasn_util_convert.py --single RIBFILE rib.dat`
  
  Alternatively just run the installer (installer.sh)
  `sh install.sh`
