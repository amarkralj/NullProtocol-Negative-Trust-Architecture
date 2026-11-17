#!/bin/sh
# Download CERT Insider Threat Test Dataset r4.2 (Carnegie Mellon University, DOI 10.1184/R1/12841247)
# Licence: research use under the ExactData end-user agreement in answers/license.txt; do not redistribute.
set -e
mkdir -p data/cert/derived && cd data/cert
curl -L -o answers.tar.bz2 https://ndownloader.figshare.com/files/24857828
curl -L -o r4.2.tar.bz2 https://ndownloader.figshare.com/files/24856766      # 4.8 GB
echo "586446b00e83ce5cdabf9dc889b0b6e7a9f44556cee3c03d39445d790122556c  r4.2.tar.bz2" | shasum -a 256 -c
tar xjf answers.tar.bz2 && tar xjf r4.2.tar.bz2 && rm r4.2.tar.bz2
# keep only the two web categories the adapter uses (the full http.csv is 14.5 GB)
LC_ALL=C awk -F, 'NR>1 { u=tolower($5); if (u ~ /wikileaks|keylog|spector|spyware|keystroke|refog|webwatcher/) print $2","$3","$4","$5 }' \
  r4.2/http.csv > derived/http_filtered.csv
