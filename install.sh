#!/bin/bash
ppath=$(which pip)
pypath=$(which python)

$ppath install pyasn
$ppath install pyOpenSSL

wget https://raw.githubusercontent.com/hadiasghari/pyasn/master/pyasn-utils/pyasn_util_download.py
wget https://raw.githubusercontent.com/hadiasghari/pyasn/master/pyasn-utils/pyasn_util_convert.py

$pypath pyasn_util_download.py --latest
export RIBFILE=$(ls *.bz2) && $pypath pyasn_util_convert.py --single $RIBFILE rib.dat

wget https://raw.githubusercontent.com/orlyjamie/asnrecon/master/asnrecon.py
