#!/usr/bin/env python
import os
import re
import argparse
from more_itertools import unique_everseen

def check_hash_type(hash_type):
	#looking for hashtypes: MD5, SHA1, SHA256
	hashes = {"MD5" : "([a-fA-F\d]{32})","SHA1" : "([a-fA-F\d]{40})","SHA256" : "([a-fA-F\d]{64})"}
	if hash_type.upper() in hashes.keys(): 
		return hashes[hash_type.upper()]
	else:
		return False

def check_file(file):
	if os.path.isfile(file):
		return True
	else:
		return False
def main(hash_type, file):
	#check the hash type, looking for three accepted styles
	hash_regex = check_hash_type(hash_type) 
	if hash_regex == False:
		print("Unknown Hash Type")
		exit()

	#check that file exists
	if check_file(file) == False:
		print("File does not exist")
		exit()

	#open file and read each line extracting hashes to array
	hashes = []

	f = open(file)
	line = f.readline()
	while line:
		for x in re.findall(hash_regex, line):
			hashes.append(x)
		line = f.readline()
	f.close()

	#get uniq hashes
	uniq_hashes = list(unique_everseen(hashes))
	return uniq_hashes
	#print("Found %d hashes matching hash format of %s using regex %s.  Only %d uniques values remain" % (len(hashes), hash_type, hash_regex, len(uniq_hashes)))


if __name__ == '__main__':
	parser = argparse.ArgumentParser()
	parser.add_argument('hash_type', type=str, help='hash style, MD5, SHA1, SHA256')
	parser.add_argument('file', type=str, help='file to extract from')

	try:
		args = parser.parse_args()
	except IOError as e:
		parser.error(e)
		sys.exit()

	hashes = main(args.hash_type, args.file)
	print('\n'.join(map(str,hashes)))
