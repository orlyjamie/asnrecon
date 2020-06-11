FROM python:2

WORKDIR /opt/asnrecon

RUN pip install pyasn
RUN pip install pyOpenSSL

RUN wget https://raw.githubusercontent.com/hadiasghari/pyasn/master/pyasn-utils/pyasn_util_download.py
RUN wget https://raw.githubusercontent.com/hadiasghari/pyasn/master/pyasn-utils/pyasn_util_convert.py

RUN python pyasn_util_download.py --latest
RUN ls -la

RUN RIBFILE=$(ls *.bz2) && python pyasn_util_convert.py --single $RIBFILE rib.dat

RUN wget https://raw.githubusercontent.com/orlyjamie/asnrecon/master/asnrecon.py

CMD python asnrecon.py
