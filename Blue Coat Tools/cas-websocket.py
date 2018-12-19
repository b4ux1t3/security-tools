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
Description: This example demonstrates using websockets to receive scan
notifications from the REST API in Content Analysis. Submit files using 
cas-submit.py. 
"""

import sys
import argparse
import json
from websocket import WebSocketConnectionClosedException
from websocket import create_connection
import ssl

def websocket_scan_thread(ws):
	while True:
		msg = ""
		try:
			msg = ws.recv()
		except WebSocketConnectionClosedException as e:
			print("Failed to receive: %s" % (e))
			return
	
		try:
			print(msg)
			msg = json.loads(msg)
			#TODO: parse fields out of the json.  Right now it just
			#      verifies that it is json
		except:
			print("Message in unexpected format: '%s'" % msg)

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
			print(r)
			print(r.content)
			return -1
		auth = r.json()
		token = auth["results"]["session_token_string"]
	
	headers = {'X-API-TOKEN': token}

	#subscribe to the websocket
	url = "ws%s://%s/rapi/ws/cas_task" % (secure_prefix, args.host)
	ws = create_connection(url, sslopt={"cert_reqs": ssl.CERT_NONE}, header=headers)
	thread = websocket_scan_thread(ws)
	thread.start();
	

if __name__ == '__main__':

	parser = argparse.ArgumentParser(description='simple CA websocket example')

	parser.add_argument('-s', '--host', default='localhost', help='CA hostname or IP address')
	parser.add_argument('-u', '--username', type=str, required=False, default='admin')
	parser.add_argument('-p', '--password', type=str, required=False, default='admin')
	parser.add_argument('-k', '--key', type=str, required=False, help='The API Key to use')
	parser.add_argument('-i', '--insecure', required=False, default=False, action='store_true')
	sys.exit(main(parser.parse_args()))
