#!/usr/bin/env python2
# -*- coding: utf-8 -*-
'''
This is a simple http sniffer made in python 2.7

Python module required => Scapy(http://www.secdev.org/projects/scapy/doc/index.html)

Copyright® 2014 Alessandro Pucci - @b4d_tR1p ; Cristian 'Tmap' Mariolini - @mariolinic

Date : 2014
Licence : GPL v3 or any later version

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.

'''

__author__ = 'b4d_tR1p - (b4d_tR1p@me.com)' ; 'Tmap - (cristian@mariolini.net)'
__version__ = '0.6'
__licence__ = 'GPL v3'

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *
import re
import csv
import sys
import sqlite3
import datetime
import time
con=sqlite3.connect('sniffez.db')
cur=con.cursor()
def create_db():
	global cur
	try:
		create_db="""CREATE TABLE IF NOT EXISTS sniffez_log(log_id INTEGER PRIMARY KEY DEFAULT (1), log_time INTEGER NOT NULL, log_data TEXT, useragent TEXT, accept TEXT, acceptlang TEXT, acceptenc TEXT, referer TEXT, cookie TEXT);"""
		cur.execute(create_db)
	except sqlite3.Error as e:
		print e.args[0]


def sniffer():
	x=0
	while x<10:
		a=sniff(filter="tcp port 80 and ip[2:2] > 40 and tcp[tcpflags] & tcp-push != 0 and dst port 80",count=1)
		parse_get(a)
	x=x+1
def parse_get(a):
	get_regex = re.compile("GET.*\\\\r\\\\n\\\\r\\\\n")
	base_request = get_regex.findall(str(a))
	request_str = [request_str.replace('\\r\\n','\n') for request_str in base_request]
	ua_match = re.search(u'User-Agent: (.*?)\\\\n', str(request_str))
	if ua_match:
		useragent= ua_match.group(1)
	else:
		useragent=None
	accept_match = re.search(u'Accept: (.*?)\\\\n', str(request_str))
	if accept_match:
		accept= accept_match.group(1)
	else:
		accept=None
	lang_match = re.search(u'Accept-Language: (.*?)\\\\n', str(request_str))
	if lang_match:
		acceptlang= lang_match.group(1)
	else:
		acceptlang=None
	acceptenc_match = re.search(u'Accept-Encoding: (.*?)\\\\n', str(request_str))
	if acceptenc_match:
		acceptenc= acceptenc_match.group(1)
	else:
		acceptenc=None
	referer_match = re.search(u'Referer: (.*?)\\\\n', str(request_str))
	if referer_match:
		referer= referer_match.group(1)
	else:
		referer=None
	cookie_match = re.search(u'Cookie: (.*?)\\\\n', str(request_str))
	if cookie_match:
		cookie= cookie_match.group(1)
	else:
		cookie=None
	if request_str:
		try:
			cur.execute("""INSERT INTO sniffez_log (log_id, log_time, log_data,useragent, accept, acceptlang,acceptenc, referer, cookie) VALUES(NULL, ?, ?,?,?,?,?,?,?)""",[int(time.time()),request_str[0],useragent, accept, acceptlang, acceptenc, referer, cookie])
			con.commit()
			print request_str[0]
		except sqlite3.Error as e:
			print "An error occurred:", e.args[0]
create_db()
sniffer()	
