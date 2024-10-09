#!/usr/bin/python3

import requests, json, subprocess, sys, jwt, base64, datetime, time
from Crypto.PublicKey import RSA
import os
import os.path
import uuid
import json
from datetime import datetime, timezone, timedelta
import argparse
import logging
import subprocess
from subprocess import Popen, PIPE, STDOUT
import multiprocessing
import tqdm

class LAPI:
	def __init__(self):
		self.__stolen_token = ""
		self.__config_url = ""
		self.__client_id = ""
		self.token = ""
		self.__domain = ""
		self.__key = None
		self.__out_dir = None
		self.__out_prefix = ""
		self.__execute_command = None
		self.token_lock = multiprocessing.Lock()

	def set_config_url(self, config_url):
		global logger
		logger.debug("Set config_url to " + config_url)
		self.__config_url = config_url
		self.load_config_url()

	def set_stolen_token(self, stolen_token):
		global logger
		logger.debug("Set stolen token to " + stolen_token)
		self.__stolen_token = stolen_token
		self.token = stolen_token

	def set_domain(self, domain):
		global logger
		logger.debug("Set domain to " + domain)
		self.__domain = domain

	def set_out_prefix(self, out_prefix):
		global logger
		logger.debug("Set out prefix to  " + out_prefix)
		self.__out_prefix = out_prefix

	def set_out_dir(self, out_dir):
		global logger
		logger.debug("Set out dir to " + out_dir)

		self.__out_dir = out_dir
		if os.path.exists(out_dir):
			logger.warning("Output folder exists:"+out_dir)
			return

		os.makedirs(out_dir)
		logger.info("Created "+out_dir)

	def set_client_id(self, client_id):
		global logger
		logger.debug("Set client id to " + client_id)
		self.__client_id = client_id

	def set_execute_command(self, execute_command):
		global logger
		logger.debug("Set execute command to " + execute_command)
		self.__execute_command = execute_command

	def load_private_key(self, private_key):
		global logger
		if os.path.isfile(private_key) == False:
			logger.error("Private key file is doesn't exists:"+private_key)
			return 1
		if os.access(private_key, os.R_OK) == False:
			logger.error("Private key file is not accessible:"+private_key)
			return 1
		f = open(private_key,'r')
		self.__key = RSA.import_key(f.read())
		logger.debug("Private key loaded")
		f.close()

	def load_config_url(self):
		global logger
		response = requests.get(self.__config_url)
		config=response.json()
		self.key_cloak_url = config["keycloak"]["url"]
		self.acapi_url = config["api"]["acapi"]
		logger.debug(self.key_cloak_url)
		logger.debug(self.acapi_url)
		return True

	def has_token_expired(self):
		global logger
		if self.token == "":
			logger.debug("Token is empty")
			return True

		js = jwt.decode(self.token, options={"verify_signature": False})
		exptime = datetime.fromtimestamp(js['exp'])
		present = datetime.now()
		if present < exptime:
			return False
		return True

	def get_token(self):
		global logger
		# generate token
		utcnow = datetime.now(timezone.utc)
		exp = int((utcnow + timedelta(minutes=5)).timestamp())
		jti = (uuid.uuid4()).hex
		claim = {"sub": self.__client_id,"aud": self.key_cloak_url + "/realms/doctors","iss": self.__client_id,"exp": exp, "jti": jti, "domain": self.__domain}
		token = jwt.encode(claim, self.__key.export_key('PEM'),algorithm='RS256')

		logger.debug("Token:"+token)
		# prepare post data
		postdata = 'client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
		postdata += '&grant_type=client_credentials'
		postdata += '&client_assertion='+token

		logger.debug("Postdata:"+postdata)
		#send POST
		resp = requests.post(self.key_cloak_url +'/realms/doctors/protocol/openid-connect/token', data = postdata, headers={'Content-type': 'application/x-www-form-urlencoded'})
		jsondata = json.loads(resp.content)
		# parse access token
		logger.debug(jsondata['access_token']) 
		return jsondata['access_token']

	def store(self, result, api):
		global logger
		if self.__out_dir == None:
			return None
		s = api[1:].replace('/', '_').replace('=','_').replace('&','_').replace('?','_').replace('!','_')

		s = self.__out_prefix + s

		fname = self.__out_dir+"/"+s+".txt"
		f = open(fname, 'w')
		f.write(result)
		f.close()
		logger.info("Saved to "+fname)
		return fname

	def get_batchId(self):
		logger.debug("get batchId from API")
		resp = json.loads(self.get("/api/batches?limit=1", do_not_process=True))
		batchId = resp["batches"][0]["id"]

		logger.debug("batchId is "+ batchId)
		return batchId

	def execute_command(self, filename=None, input=None):
		global logger
		retval = False
		if self.__execute_command == None:
			logger.debug("There is no command set to execute!")
			return False

		if filename:
			l = self.__execute_command.split()
			l.append(filename)
			logger.info("Executing :'" + " ".join(l) + "'")
			subprocess.run(l)
			retval = True

		if input:
			logger.info("Processing response with '" + self.__execute_command + "'")
			process = subprocess.Popen(self.__execute_command.split(), stdin=subprocess.PIPE, text=True)
			process.communicate(input)
			#process = subprocess.Popen(self.__execute_command.split(), stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
			#output, _ = process.communicate(input)
			#print(output)
			retval = True

		return retval
			
	def check_and_update_token(self):
		self.token_lock.acquire()
		try:
			if self.has_token_expired() == True:
				if self.__stolen_token != "":
					logger.error("stolen token expired")
				else:
					self.token = self.get_token()
		finally:
			self.token_lock.release()

	def process_response(self, response, api):
		if self.__out_dir:
			# save to file	
			fname = self.store(response.text, api)
			self.execute_command(filename=fname)
			return

		if self.execute_command(input=response.text) == False: 
			logger.info(api+" : " + response.text)
	
    
	def get(self, api, deviceId=None, do_not_process=False):
		global logger
		logger.debug("Getting raw api:"+api)
		# check&update token
		self.check_and_update_token()

		# prepare API URL
		api = api.format(deviceId=deviceId)
		logger.info("Getting " + api)

		# prepare header
		self.token_lock.acquire()
		headers = {	'authorization': 'Bearer ' + self.token, 
					'accept' : 'application/json, text/plain, */*', 
					'content-type': 'application/json'}
		self.token_lock.release()

		# make GET call
		start = datetime.now()
		response = requests.get(self.acapi_url+api, headers=headers)
		end = datetime.now()

		logger.info("Done " +  api + " in "+str(end-start));
		# check response
		if response.status_code != 200:                                                                                                                                                
			logger.error("!!!!!ERROR:Something went wrong" + api + " status code: "+str(response.status_code))  
			logger.error(response.content)
			return None

		logger.debug("Response " + api + ":" + response.text)
		# process response
		if do_not_process == False:
			self.process_response(response, api)

		return response.text


APIS=[
	# batch APIs
	{'name':'batches',				'URL':"/api/batches?limit=25"},
	{'name':'batches_cures',		'URL':"/api/batches/{batchId}/devices/{deviceId}/home/cures?limit=25"},
	{'name':'batches_diagnosis',	'URL':"/api/batches/{batchId}/devices/{deviceId}/home/diagnoses?limit=25"},
	{'name':'batches_topology',		'URL':"/api/batches/{batchId}/devices/{deviceId}/home/topology"},
	{'name':'batches_hosts',		'URL':"/api/batches/{batchId}/devices/{deviceId}/hosts"},
	{'name':'batches_stations',		'URL':"/api/batches/{batchId}/devices/{deviceId}/stations"},
	{'name':'batches_experience_index',		'URL':"/api/batches/{batchId}/devices/{deviceId}/topology/experience_index"},
	{'name':'batches_experience_index_1_5',	'URL':"/api/batches/{batchId}/devices/{deviceId}/topology/experience_index_1_5"},

	# gateway APIs
	{'name':'gateway',				'URL':"/api/gateway/{deviceId}"},
	{'name':'gateway_topology',		'URL':"/api/gateway/{deviceId}/topology"},
	{'name':'gateway_station',		'URL':"/api/gateway/{deviceId}/station"},
	{'name':'gateway_interfaces',	'URL':"/api/gateway/{deviceId}/radio/{radioId}/interfaces"},

	# direct device APIs
	{'name':'direct_reboot',		'URL':"/api/direct/{deviceId}/device/reboot?type=reboot&delay=0"},
	{'name':'direct_reset',			'URL':"/api/direct/{deviceId}/device/reboot?type=reset&delay=0"},
	{'name':'direct_factory_reset',	'URL':"/api/direct/{deviceId}/device/reboot?type=factory_reset&delay=0"},

	# direct home APIs
	{'name':'direct_topology',		'URL':"/api/direct/{deviceId}/home/topology"},
	{'name':'direct_stations',		'URL':"/api/direct/{deviceId}/home/stations"},
	{'name':'direct_hosts',			'URL':"/api/direct/{deviceId}/home/hosts"},
	{'name':'direct_service_info',	'URL':"/api/direct/{deviceId}/home/service_info"},
	{'name':'direct_ssids',			'URL':"/api/direct/{deviceId}/home/ssids?include=security_section"},
	{'name':'direct_station_policies',	'URL':"/api/direct/{deviceId}/home/station_policies"},

	# device raw avro data
	{'name':'device_raw',	'URL':"/api/devices/{deviceId}/raw"}
]

def add_APIs(parser):
    for api in APIS:
        n = '--'+api['name'].replace('_', '-')
        #print('Adding API:'+api['name']+':'+api['URL'])
        parser.add_argument(n, help=api['URL'], action="store_true")


def mget(api):
    global lapi
    lapi.get(api)

def execute_apis(apis, multi):
	global lapi

	lapi.check_and_update_token()

	pool = multiprocessing.Pool(processes=multi)
	#pool.map(mget, apis)
	for _ in tqdm.tqdm(pool.imap_unordered(mget, apis), total=len(apis)):
		pass

def get_batchId():
	global lapi
	global batchId

	if batchId == "":
		batchId = lapi.get_batchId()
	return batchId

def add_apis(apis, args, device):
	batchId = ""
	for api in APIS:
		if getattr(args, api['name']):
			if "/{batchId}/" in api['URL']:
				if batchId == "":
					batchId = get_batchId()
			s = api['URL'].format(deviceId=device, batchId=batchId, radioId=args.radio_id)
			apis.append(s)
	

def main():
	global logger
	global lapi
	global apis
	global batchId

	batchId = ""

	logger = logging.getLogger(__name__)
	logger.setLevel(logging.INFO)

	parser = argparse.ArgumentParser()
	parser.add_argument("-c", "--config-file", 		help="config file for DOMAIN, CONFIG URL, etc.", required=True)
	parser.add_argument("-o", "--out-dir", 			help="output directory, stores outputs to this directory if this parameter is set")
	parser.add_argument("-p", "--out-prefix", 		help="add this prefix to output files if --out-dir is set")
	parser.add_argument("-i", "--print-log-info", 	help="print extra logging info, level, datetime, etc", action="store_true")
	parser.add_argument("-v", "--log-level", 		help="set log level; 10: DEBUG, 20: INFO(Default), 30: WARNING, 40: ERROR, 50:CRITICAL", type=int)
	parser.add_argument("-t", "--token", 			help="set token(you may steal it from browser)")
	parser.add_argument("-e", "--execute-command",	help="execute command after each API call, i.e 'jq .'")
	parser.add_argument("-m", "--multi",			help="Multi process count, default=1", type=int, default=1)
	parser.add_argument("-l", "--device-list", 		help="device list file")
	parser.add_argument("-d", "--device-id", 		help="device id(Serial Number)")
	parser.add_argument("-b", "--batch-id", 		help="set batchId to use")
	parser.add_argument("-r", "--radio-id", 		help="set radioId to use")
	parser.add_argument("-a", "--api", 				help="API URL, i.e. /api/direct/JT34A7102/home/stations")

	add_APIs(parser)

	args = parser.parse_args()

	# set logging params
	if args.log_level:
		logger.setLevel(args.log_level)

	FORMAT = "%(message)s"
	if args.print_log_info:
		#FORMAT = "[%(asctime)s][%(filename)s:%(lineno)s - %(funcName)10s() ] [%(levelname)s] %(message)s"
		FORMAT = "[%(asctime)s][%(filename)s:%(lineno)04s][%(levelname)7s]: %(message)s"
	
	logging.basicConfig(format=FORMAT)

	# if no config, there is nothing to do
	if args.config_file == None:
		logger.error("provide a config file with necessary information")
		return 1

	# load config
	json_file = open(args.config_file)
	config = json.load(json_file)
	json_file.close()

	lapi = LAPI()

	# set domain
	if "domain" not in config:
		logger.error("Please provide domain in config file")
		return False

	lapi.set_domain(config["domain"])

	# set config url
	if "config_url" not in config.keys():
		logger.error("Please provide config url in config file")
		return False

	lapi.set_config_url(config["config_url"])

	# batchId
	if args.batch_id:
		batchId = args.batch_id

	# stolen token
	if args.token:
		lapi.set_stolen_token(args.token)
	

	if not args.token:
		# token is not set, get it from JWT via private key and client id
		if "private_key" not in config:
			logger.error("Please provide private_key file in config file")
			return False

		if "client_id" not in config:
			logger.error("Please provide client_id in config file")
			return False

	lapi.load_private_key(config["private_key"])
	lapi.set_client_id(config["client_id"])

	# set output params
	if args.out_dir:
		lapi.set_out_dir(args.out_dir)

	if args.out_prefix:
		lapi.set_out_prefix(args.out_prefix)

	# set execute command
	if args.execute_command:
		lapi.set_execute_command(args.execute_command)

	# execute the request
	# get API
	if args.api:
		lapi.get(args.api)

	apis = []
	# get Device
	if args.device_id:
		add_apis(apis, args, args.device_id)

	# get Device List
	if args.device_list:
		with open(args.device_list) as file:
			lines = [line.rstrip().lstrip() for line in file]
		for d in lines:
			add_apis(apis, args,d)
	
	execute_apis(apis, args.multi)

if __name__ == "__main__":
	main()
