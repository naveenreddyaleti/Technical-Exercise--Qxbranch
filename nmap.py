#! /usr/bin/python

import pymongo
import argparse
import sys
import os
import subprocess

# Provide a helpful API to user
arg_parser = argparse.ArgumentParser("Vulnerability Scanning")
arg_parser.add_argument("-u","--url",required=True, help="Enter the url")

args = arg_parser.parse_args()

# Establish a connection to the MongDB server
conn = pymongo.MongoClient()

# Retrieve a handle to the "Qxbranch" database
db = conn["Qxbranch"]

# Retrieve a handle to the "analysis" collection
coll = db["analysis"]

# Empty dictionary representing the file data object
vulscan_object = {}


nmap_proc = subprocess.Popen(["nmap", "-v","-A" ,args.url], stdout=subprocess.PIPE)

for result_line in nmap_proc.stdout:
  
  data = result_line.decode('utf-8').strip().split(':')
  if data[0] == '| MD5':
    vulscan_object["MD5"] = data[1]
  elif data[0] == '|_SHA-1':
    vulscan_object["SHA-1"] = data[1]
  elif data[0] == '| Signature Algorithm':
    vulscan_object["Signature_Algorithm"] = data[1]
  elif data[0] == '| Public Key type':
    vulscan_object["Public_Key_type"] = data[1]
  elif data[0] == '| Public Key bits':
    vulscan_object["Public_Key_bits"] = data[1]
  elif  data[0] == '|_http-server-header':
    vulscan_object["http_server"] = data[1]
  port_data = result_line.decode('utf-8').strip().split( )
  try:
   if port_data[0] == 'Discovered':
     vulscan_object["port_data"] = data[3]
  except Exception:
   pass
 # Complete exectution, then close handle
nmap_proc.wait()
nmap_proc = None
coll.insert(vulscan_object)
print("Added to database: " + repr(vulscan_object))
sys.exit(0)
