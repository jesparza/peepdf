#!/usr/bin/env python

#
#	peepdf is a tool to analyse and modify PDF files
#	http://peepdf.eternal-todo.com
#	By Jose Miguel Esparza <jesparza AT eternal-todo.com>
#
#	Copyright (C) 2011 Jose Miguel Esparza
#
#	This file is part of peepdf.
#
#		peepdf is free software: you can redistribute it and/or modify
#		it under the terms of the GNU General Public License as published by
#		the Free Software Foundation, either version 3 of the License, or
#		(at your option) any later version.
#
#		peepdf is distributed in the hope that it will be useful,
#		but WITHOUT ANY WARRANTY; without even the implied warranty of
#		MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	See the
#		GNU General Public License for more details.
#
#		You should have received a copy of the GNU General Public License
#		along with peepdf.	If not, see <http://www.gnu.org/licenses/>.
#

'''
	Initial script to launch the tool
'''

import sys, os, optparse, re, urllib2, datetime, hashlib
from PDFConsole import PDFConsole
from PDFCore import PDFParser
try:
	from spidermonkey import Runtime
	JS_MODULE = True 
except:
	JS_MODULE = False


def getRepPaths(url, path = ''):
	paths = []
	dumbReDirs = '<li><a[^>]*?>(.*?)/</a></li>'
	dumbReFiles = '<li><a[^>]*?>([^/]*?)</a></li>'
	
	try:
		browsingPage = urllib2.urlopen(url+path).read()
	except:
		sys.exit('[x] Connection error while getting browsing page "'+url+path+'"')
	dirs = re.findall(dumbReDirs, browsingPage)
	files = re.findall(dumbReFiles, browsingPage)
	for file in files:
		if file != '..':
			if path == '':
				paths.append(file)
			else:
				paths.append(path + '/' + file)
	for dir in dirs:
		if path == '':
			dirPaths = getRepPaths(url, dir)
		else:
			dirPaths = getRepPaths(url, path+'/'+dir)
		paths += dirPaths
	return paths

def getLocalFilesInfo(filesList):
	localFilesInfo = {}
	print '[-] Getting local files information...'
	for path in filesList:
		if os.path.exists(path):
			content = open(path,'r').read()
			shaHash = hashlib.sha256(content).hexdigest()
			localFilesInfo[path] = shaHash
	print '[+] Done'
	return localFilesInfo

	
author = 'Jose Miguel Esparza' 
email = 'jesparza AT eternal-todo.com'
url = 'http://peepdf.eternal-todo.com'
twitter = 'http://twitter.com/EternalTodo'
peepTwitter = 'http://twitter.com/peepdf'
version = '0.1'
revision = '78'   
stats = ''
pdf = None
fileName = None
newLine = os.linesep
vulnsDict = {'/JBIG2Decode':'CVE-2009-0658','mailto':'CVE-2007-5020','Collab.collectEmailInfo':'CVE-2007-5659','util.printf':'CVE-2008-2992','getAnnots':'CVE-2009-1492','getIcon':'CVE-2009-0927','spell.customDictionaryOpen':'CVE-2009-1493','media.newPlayer':'CVE-2009-4324','doc.printSeps':'CVE-2010-4091','/U3D':['CVE-2009-3953','CVE-2009-3959','CVE-2011-2462'],'/PRC':'CVE-2011-4369'}
versionHeader = 'Version: peepdf ' + version + ' r' + revision
peepdfHeader =  versionHeader + newLine*2 +\
               url + newLine +\
               peepTwitter + newLine*2 +\
               author + newLine +\
               email + newLine +\
               twitter + newLine
               
argsParser = optparse.OptionParser(usage='Usage: '+sys.argv[0]+' [options] PDF_file',description=versionHeader)
argsParser.add_option('-i', '--interactive', action='store_true', dest='isInteractive', default=False, help='Sets console mode.')
argsParser.add_option('-s', '--load-script', action='store', type='string', dest='scriptFile', help='Loads the commands stored in the specified file and execute them.')
argsParser.add_option('-f', '--force-mode', action='store_true', dest='isForceMode', default=False, help='Sets force parsing mode to ignore errors.')
argsParser.add_option('-l', '--loose-mode', action='store_true', dest='isLooseMode', default=False, help='Sets loose parsing mode to catch malformed objects.')
argsParser.add_option('-u', '--update', action='store_true', dest='update', default=False, help='Updates peepdf with the latest files from the repository.')
argsParser.add_option('-v', '--version', action='store_true', dest='version', default=False, help='Shows program\'s version number.')
(options, args) = argsParser.parse_args()

if options.version:
	print peepdfHeader
elif options.update:
	updated = False
	newVersion = ''
	localVersion = 'v'+version+' r'+revision
	reVersion = 'version = \'(\d\.\d)\'\s*?revision = \'(\d+)\''
	repURL = 'http://peepdf.googlecode.com/svn/trunk/'
	print '[-] Checking if there are new updates...'
	try:
		remotePeepContent = urllib2.urlopen(repURL+'peepdf.py').read()
	except:
		sys.exit('[x] Connection error while getting file "'+path+'"')
	repVer = re.findall(reVersion, remotePeepContent)
	if repVer != []:
		newVersion = 'v'+repVer[0][0]+' r'+repVer[0][1]
	else:
		sys.exit('[x] Error getting the version number from the repository')
	if localVersion == newVersion:
		print '[+] No changes! ;)'
	else:
		print '[+] There are new updates!!'
		print '[-] Getting paths from the repository...'
		pathNames = getRepPaths(repURL,'')
		print '[+] Done'
		localFilesInfo = getLocalFilesInfo(pathNames)
		print '[-] Checking files...'
		for path in pathNames:
			try:
				fileContent = urllib2.urlopen(repURL+path).read()
			except:
				sys.exit('[x] Connection error while getting file "'+path+'"')
			if localFilesInfo.has_key(path):
				# File exists
				# Checking hash
				shaHash = hashlib.sha256(fileContent).hexdigest()
				if shaHash != localFilesInfo[path]:
					open(path,'w').write(fileContent)
					print '[+] File "'+path+'" updated successfully'
			else:
				# File does not exist
				index = path.rfind('/')
				if index != -1:
					dirsPath = path[:index]
					if not os.path.exists(dirsPath):
						print '[+] New directory "'+dirsPath+'" created successfully'
						os.makedirs(dirsPath)
				open(path,'w').write(fileContent)
				print '[+] New file "'+path+'" created successfully'
		message = '[+] peepdf updated successfully'
		if newVersion != '':
			message += ' to '+newVersion
		print message
		
else:
	if len(args) == 1:
		fileName = args[0]
		if not os.path.exists(fileName):
			sys.exit('Error: The file "'+fileName+'" does not exist!!')
	elif len(args) > 1 or (len(args) == 0 and not options.isInteractive):
		sys.exit(argsParser.print_help())
		
	if options.scriptFile != None:
		if not os.path.exists(options.scriptFile):
			sys.exit('Error: The script file "'+options.scriptFile+'" does not exist!!')
		
	if fileName != None:
		if not JS_MODULE:
			stats += 'Warning: Spidermonkey is not installed!!'+newLine
		pdfParser = PDFParser()
		ret,pdf = pdfParser.parse(fileName, options.isForceMode, options.isLooseMode)
		errors = pdf.getErrors()
		for error in errors:
			if error.find('Decryption error') != -1:
				stats += error + newLine
		if stats != '':
			stats += newLine
		statsDict = pdf.getStats()
		stats += 'File: ' + statsDict['File'] + newLine
		stats += 'MD5: ' + statsDict['MD5'] + newLine
		stats += 'Size: ' + statsDict['Size'] + ' bytes' + newLine
		stats += 'Version: ' + statsDict['Version'] + newLine
		stats += 'Binary: ' + statsDict['Binary'] + newLine
		stats += 'Linearized: ' + statsDict['Linearized'] + newLine
		stats += 'Encrypted: ' + statsDict['Encrypted']
		if statsDict['Encryption Algorithms'] != []:
			stats += ' ('
			for algorithmInfo in statsDict['Encryption Algorithms']:
				stats += algorithmInfo[0] + ' ' + str(algorithmInfo[1]) + ' bits, '
			stats = stats[:-2] + ')' + newLine
		stats += 'Updates: ' + statsDict['Updates'] + newLine
		stats += 'Objects: ' + statsDict['Objects'] + newLine
		stats += 'Streams: ' + statsDict['Streams'] + newLine
		stats += 'Comments: ' + statsDict['Comments'] + newLine
		stats += 'Errors: ' + statsDict['Errors'] + newLine*2
		for version in range(len(statsDict['Versions'])):
			statsVersion = statsDict['Versions'][version]
			stats += 'Version ' + str(version) + ':' + newLine
			if statsVersion['Catalog'] != None:
				stats += '\tCatalog: ' + statsVersion['Catalog'] + newLine
			else:
				stats += '\tCatalog: No' + newLine
			if statsVersion['Info'] != None:
				stats += '\tInfo: ' + statsVersion['Info'] + newLine
			else:
				stats += '\tInfo: No' + newLine
			stats += '\tObjects ('+statsVersion['Objects'][0]+'): ' + statsVersion['Objects'][1] + newLine
			if statsVersion['Compressed Objects'] != None:
				stats += '\tCompressed objects ('+statsVersion['Compressed Objects'][0]+'): ' + statsVersion['Compressed Objects'][1] + newLine
			if statsVersion['Errors'] != None:
				stats += '\t\tErrors ('+statsVersion['Errors'][0]+'): ' + statsVersion['Errors'][1] + newLine
			stats += '\tStreams ('+statsVersion['Streams'][0]+'): ' + statsVersion['Streams'][1]
			if statsVersion['Xref Streams'] != None:
				stats += newLine + '\t\tXref streams ('+statsVersion['Xref Streams'][0]+'): ' + statsVersion['Xref Streams'][1]
			if statsVersion['Object Streams'] != None:
				stats += newLine + '\t\tObject streams ('+statsVersion['Object Streams'][0]+'): ' + statsVersion['Object Streams'][1]
			if int(statsVersion['Streams'][0]) > 0:
				stats += newLine + '\t\tEncoded ('+statsVersion['Encoded'][0]+'): ' + statsVersion['Encoded'][1]
				if statsVersion['Decoding Errors'] != None:
					stats += newLine + '\t\tDecoding errors ('+statsVersion['Decoding Errors'][0]+'): ' + statsVersion['Decoding Errors'][1]
			if statsVersion['Objects with JS code'] != None:
				stats += newLine + '\tObjects with JS code ('+statsVersion['Objects with JS code'][0]+'): ' + statsVersion['Objects with JS code'][1]
			actions = statsVersion['Actions']
			events = statsVersion['Events']
			vulns = statsVersion['Vulns']
			elements = statsVersion['Elements']
			if events != None or actions != None or vulns != None or elements != None:
				stats += newLine + '\tSuspicious elements:' + newLine
				if events != None:
					for event in events:
						stats += '\t\t' + event + ': ' + str(events[event]) + newLine
				if actions != None:
					for action in actions:
						stats += '\t\t' + action + ': ' + str(actions[action]) + newLine
				if vulns != None:
					for vuln in vulns:
						if vulnsDict.has_key(vuln):
							vulnString = str(vulnsDict[vuln])
							if vulnString.find('[') != -1:
								vulnString = vulnString[1:-1] 
							stats += '\t\t' + vuln + ' (' + vulnString +'): ' + str(vulns[vuln]) + newLine
						else:
							stats += '\t\t' + vuln + ': ' + str(vulns[vuln]) + newLine
				if elements != None:
					for element in elements:
						if vulnsDict.has_key(element):
							vulnString = str(vulnsDict[element])
							if vulnString.find('[') != -1:
								vulnString = vulnString[1:-1] 
							stats += '\t\t' + element + ' (' + vulnString +'): ' + str(elements[element]) + newLine
						else:
							stats += '\t\t' + element + ': ' + str(elements[element]) + newLine
			urls = statsVersion['URLs']
			if urls != None:
				newLine + '\tFound URLs:' + newLine
				for url in urls:
					stats += '\t\t' + url + newLine
			stats += newLine * 2
		
	if options.scriptFile != None:
		scriptFileObject = open(options.scriptFile,'r')
		console = PDFConsole(pdf,stdin=scriptFileObject)
		try:
			console.cmdloop()
		finally:
			scriptFileObject.close()
	elif options.isInteractive:
		console = PDFConsole(pdf)
		console.cmdloop(stats + newLine)
	elif fileName != None:
		print stats