#!/bin/sh
# CERT Insider Threat Test Dataset r6.2 (Carnegie Mellon University, DOI 10.1184/R1/12841247); research use under the
# ExactData end-user agreement (answers/license.txt); do not redistribute. 22.7 GB compressed. The archive is read as a
# stream: every file except http.csv is extracted, and http.csv is filtered on the fly to the two web categories the
# adapter uses, so the full web log (tens of GB) never touches the disk. Nothing in the archive is executed.
set -e
cd data/cert
curl -L -C - --retry 5 -o r6.2.tar.bz2 https://ndownloader.figshare.com/files/24844280
echo "6396bc0d6eb1d806ded0a70aaa3f111a5dcbb56269130e854c415e4e1b8eb3e9  r6.2.tar.bz2" | shasum -a 256 -c
mkdir -p derived/r6.2
tar xjf r6.2.tar.bz2 --exclude '*/http.csv'
tar xjOf r6.2.tar.bz2 '*/http.csv' 2>/dev/null | LC_ALL=C awk -F, '{ u=tolower($5); if (u ~ /wikileaks|keylog|spector|spyware|keystroke|refog|webwatcher/) print $2","$3","$4","$5 }' \
  > derived/r6.2/http_filtered.csv
rm r6.2.tar.bz2
echo done
