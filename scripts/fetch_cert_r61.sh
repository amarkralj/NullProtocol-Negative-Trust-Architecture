#!/bin/sh
# CERT Insider Threat Test Dataset r6.1 (Carnegie Mellon University, DOI 10.1184/R1/12841247); research use under the
# ExactData end-user agreement; do not redistribute. 20.4 GB compressed. Used only as an untouched final test set.
# Streamed like r6.2: every file except http.csv is extracted; http.csv is filtered on the fly (leak-site / spyware
# categories and uploads) and never stored in full. Nothing in the archive is executed.
set -e
cd data/cert
curl -L -C - --retry 5 -o r6.1.tar.bz2 https://ndownloader.figshare.com/files/24848018
echo "50232e47b694e6daf8147248d700b5b7db1fdeb69981c5a596e88c302abd2681  r6.1.tar.bz2" | shasum -a 256 -c
mkdir -p derived/r6.1
tar xjf r6.1.tar.bz2 --exclude '*/http.csv'
tar xjOf r6.1.tar.bz2 '*/http.csv' 2>/dev/null | LC_ALL=C awk -F, -v F=derived/r6.1/http_filtered.csv -v U=derived/r6.1/http_uploads.csv '
  { u=tolower($5); if (u ~ /wikileaks|keylog|spector|spyware|keystroke|refog|webwatcher/) print $2","$3","$4","$5 > F;
    if ($6=="WWW Upload") print $2","$3","$4","$5 > U }'
touch derived/r6.1/http_filtered.csv derived/r6.1/http_uploads.csv
rm r6.1.tar.bz2
echo done
