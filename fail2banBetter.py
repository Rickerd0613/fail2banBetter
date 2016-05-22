#!/usr/bin/python

import re
import config
import os
import time
import sys


def whitelistCheck(ip):
	whitelistFile = open('whitelist', 'r')

	for whitelistLine in whitelistFile:
		whitelistMatch = re.match(whitelistLine.rstrip(), ip)
		if whitelistMatch:
			whitelistFile.close()
			return 1
	whitelistFile.close()
	return 0

def blacklistCheck(ip):
	blacklistFile = open('blacklist', 'r')

	for blacklistLine in blacklistFile:
		blacklistMatch = re.match(blacklistLine.rstrip(), ip)
		if blacklistMatch:
			blacklistFile.close()
			return 1
	blacklistFile.close()
	return 0

def writeToLog(action, ip, line="N/A", service="Null"):
	clientLogFile = open('fail2banBetter.log', 'a')

	if action is "ban":
		clientLogFile.write("Banned[" + service + "][" + ip + "]: " + "\"" + line.rstrip() + "\"\n")
	if action is "unban":
		clientLogFile.write("Unbanned[" + service + "][" + ip + "]:\n")
	if action is "whitelist":
		clientLogFile.write("Whitelisted[" + service + "][" + ip + "]:\n")
	if action is "logfileChange":
		clientLogFile.write("Log file changed for[" + service + "]\n")

	clientLogFile.close()

def banIp(ip, line=None, service="Null"):
	blacklistFile = open('blacklist', 'a')
	blacklistFile.write(ip + "\n")
	blacklistFile.close()

	os.system("iptables -A INPUT -s " + ip + " -j DROP")

	writeToLog("ban", ip, line, service)
	#unbanIp(ip, line, service)

def unbanIp(ip, line=None, service="Null"):
	blacklistFile = open('blacklist', 'r')
	blacklistLines = blacklistFile.readlines()
	blacklistFile.close()

	blacklistFile = open('blacklist', 'w')
	for ipLine in blacklistLines:
		if ipLine != ip + "\n":
			blacklistFile.write(ipLine)
	blacklistFile.close()

	os.system("iptables -D INPUT -s " + ip + " -j DROP")
	writeToLog("unban", ip, line, service)

def parseLog(regex, logFileLocation, service="Null"):
	logFile = open(logFileLocation, 'r')

	for line in logFile:
		ipMatch = re.search(regex.rstrip(), line.rstrip())
		if ipMatch:
			ip = ipMatch.group(1)
			if (whitelistCheck(ip) == 0 and blacklistCheck(ip) == 0):
				banIp(ip, line, service)

	logFile.close()

def findMatch(regexFileLocation, logFileLocation, service="Null"):
	regexFile = open(regexFileLocation, 'r')

	for regexLine in regexFile:
		parseLog(regexLine.rstrip(), logFileLocation, service)

	regexFile.close()

if sys.argv[1] == "reban":
	blacklistFile = open('blacklist', 'r')
	for ip in blacklistFile:
		os.system("iptables -A INPUT -s " + ip.rstrip() + " -j DROP")
	blacklistFile.close()
	sys.exit("rebanned")

while (1 == 1):

	if (os.path.getsize(config.ssh['log']) != config.ssh['lastLogSize']):
		config.ssh['lastLogSize'] = os.path.getsize(config.ssh['log'])
		writeToLog("logfileChange", None, None, "ssh")
		findMatch(config.ssh['regex'], config.ssh['log'], "ssh")

	if (os.path.getsize(config.apache['log']) != config.apache['lastLogSize']):
		config.apache['lastLogSize'] = os.path.getsize(config.apache['log'])
		writeToLog("logfileChange", None, None, "apache")
		findMatch(config.apache['regex'], config.apache['log'], "apache")

	if (os.path.getsize(config.vnc['log']) != config.vnc['lastLogSize']):
		config.vnc['lastLogSize'] = os.path.getsize(config.vnc['log'])
		writeToLog("logfileChange", None, None, "vnc")
		findMatch(config.vnc['regex'], config.vnc['log'], "vnc")

	time.sleep(10)
