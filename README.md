usage:
python virus_total_scanner.py --key [vt key] --dir [output directory] [hashtype] [file with hashes]

example:
python virus_total_scanner.py --key xxxxxx --dir output sha256 2019-02-13-data_export.csv


output for each hash will end up in the output directory under a file name based on the hash.  Then grep for virus hits:
egrep "positives.{20}" -o -R *
