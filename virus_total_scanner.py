#!/usr/bin/env python
import os
import sys
import json
import urllib2
import hashlib
import argparse
import requests
import hash_extracter
import time

VIRUSTOTAL_URL = 'https://www.virustotal.com/vtapi/v2/file/report'
API_KEY = ''
OUTPUT_DIR = "output"
SLEEP_TIME = 20

class Scanner(object):
	def __init__(self, key, hashes, directory):
		self.key = key
		self.hashes = hashes
		self.previously_completed = []
		self.directory = directory

	def scan(self, check_hash_index):
		data = 'apikey=' + self.key + "&" + 'resource=' + self.hashes[check_hash_index]
		try:
			#print(VIRUSTOTAL_URL, data)
			r = requests.post(url = VIRUSTOTAL_URL, data = data) 
			#print(r.text)
			f = open(self.directory + "/" + self.hashes[check_hash_index], "w")
			f.write(r.text)
			f.close()
		except Exception as e:
			print("[!] ERROR: Cannot obtain results from VirusTotal: {0}\n".format(e))
			return

	def run(self):
		if not self.key:
			print("[!] ERROR: You didn't specify a valid VirusTotal API key.\n")
			return
		#check all hashes against hashes in directory
		if os.path.isdir(self.directory):
			for item in os.listdir(self.directory):
				if os.path.isfile(os.path.join(self.directory, item)):
					self.previously_completed.append(item)
			self.hashes = list(set(self.hashes) - set(self.previously_completed))
			print("Going to scan " + str(len(self.hashes)) + " hashes.")
			for i in range(len(self.hashes)):
				print("Scanning hash: " + self.hashes[i])
				self.scan(i)
				time.sleep(SLEEP_TIME)
		else:
			print("[!] ERROR: Output directory: \"" + self.directory + "\" is not a directory.\n")
			exit()
		#self.scan()

if __name__ == '__main__':
	parser = argparse.ArgumentParser()
	parser.add_argument('--key', type=str, action='store', default=API_KEY, help='VirusTotal API key')
	parser.add_argument('--dir', type=str, action='store', default=OUTPUT_DIR, help='Output Directory')
	parser.add_argument('hash_type', type=str, help='hash style, MD5, SHA1, SHA256')
	parser.add_argument('file', type=str, help='file to extract from')

	try:
		args = parser.parse_args()
	except IOError as e:
		parser.error(e)
		sys.exit()

	#get hashes
	hashes = hash_extracter.main(args.hash_type, args.file)
	#print(len(hashes))
	scan = Scanner(args.key, hashes, args.dir)
	scan.run()