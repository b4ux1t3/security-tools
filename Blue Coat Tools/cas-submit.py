#-------------------------------------------------------------------------------
# Dependencies: websocket-client, requests
#
# websocket-client can be downloaded from:
#    https://pypi.python.org/pypi/websocket-client
#
# requests can be downloaded from:
#    https://codeload.github.com/kennethreitz/requests/legacy.tar.gz/master
#
# Code revised and fixed by Chris Pilcher 5/30/2018
#-------------------------------------------------------------------------------

"""
Description: This example submits files to Content Analysis for evaluation over 
the REST API.  You should first subscribe to the websocket using cas-websocket.py 
in order to see the responses.
"""

import sys
import argparse
import json
import ssl
import requests
import os.path

def main(args):
	secure_prefix="s"
	if bool(args.insecure):
		secure_prefix=""
	token = args.key

	# If no API key is specified, try to acquire one
	if len(token) == 0:
		# Authenticate and get a token
		auth_url = "http%s://%s/rapi/auth/session" % (secure_prefix, args.host)
		auth_message = { 'username': args.username, 'password': args.password }
		r = requests.post(auth_url, data=auth_message, verify=False)
		if not r.ok:
			print("failed to authenticate")
			print (r)
			print (r.content)
			return -1
		auth = r.json()
		token = auth["results"]["session_token_string"]
	
	headers = {'X-API-TOKEN': token, 'X-Response-Wait-MS': 1000}

	#CA scan request
	basename = os.path.basename(args.file.name)
	ma_files = { basename: (basename, args.file, 'application/octet-stream') }
	scan_url = "http%s://%s/rapi/cas/scan?token=%s" % (secure_prefix, args.host, token)
	r = requests.post(scan_url, files=ma_files, verify=False, headers=headers)
	if not r.ok:
		print("Failed to scan Content Analysis")
		print(r)
		print(r.content)
		ws.abort()
		return -1
	print("Success!")
	print(r.json())

if __name__ == '__main__':

	parser = argparse.ArgumentParser(description='simple CA websocket example')

	parser.add_argument('-s', '--host', default='localhost', help='CA hostname or IP address')
	parser.add_argument('-u', '--username', type=str, required=False, default='admin')
	parser.add_argument('-p', '--password', type=str, required=False, default='admin')
	parser.add_argument('-o', '--owner', type=str, required=False, default='admin')
	parser.add_argument('-f', '--file', type=argparse.FileType('rb'), required=True)
	parser.add_argument('-k', '--key', type=str, required=False, help='The API Key to use')
	parser.add_argument('-i', '--insecure', required=False, default=False, action='store_true')
	sys.exit(main(parser.parse_args()))