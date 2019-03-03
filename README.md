Python Scripts to grep out hashes from a file and send them to virustotal for hash checks.  The intended use is to take SEIM or log data on file hashes and find the malware.  The script requires an API key to query VT.  With a free api key the script is throttled to one hash check every 20 sec.  Remove this throttle if you have an enterprise key.

### usage:
```
python virus_total_scanner.py --key [vt key] --dir [output directory] [hashtype] [file with hashes]
```

### example:
```
python virus_total_scanner.py --key xxxxxx --dir output sha256 data_export.csv
```

output for each hash will end up in the output directory under a file name based on the hash.  Then grep for virus hits:
egrep "positives.{20}" -o -R *
