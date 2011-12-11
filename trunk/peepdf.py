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

import sys, os, optparse, re, urllib2, datetime
from PDFConsole import PDFConsole
from PDFCore import PDFParser
try:
	from spidermonkey import Runtime
	JS_MODULE = True 
except:
	JS_MODULE = False


def getRepFilesInfo(url, path = ''):
	filesInfoDic = {} 
	dumbReDirs = '<a\s*?onclick="ret[^>]*?>(.*?)</a>'
	dumbReFiles = '<a\s*?onclick="_[^>]*?>(.*?)</a>'
	dumbReSize = '<div>Size: (\S*?) bytes[^<]*?</div>'
	print '[-] Getting repository files information from "'+url+path+'"...'
	try:
		browsingPage = urllib2.urlopen(url+path).read()
	except:
		sys.exit('[x] Connection error while getting browsing page "'+browsePath+'"')
	dirs = re.findall(dumbReDirs, browsingPage)
	filesInfo = re.findall(dumbReFiles, browsingPage)
	if filesInfo != [] and len(filesInfo) % 5 == 0:
		for i in range(0,len(filesInfo),5):
			pathFile = path+filesInfo[i]
			fileDate = filesInfo[i+3]
			# Get date
			#TODO: check Yesterday??
			if fileDate.find('Today') != -1:
				fileDate = datetime.datetime.today()
			elif fileDate.find('(') != -1:
				fileDate = fileDate[:fileDate.find('(')]
				year = datetime.datetime.today().strftime('%Y')
				fileDate = datetime.datetime.strptime(fileDate + year,'%b %d %Y')
			else:
				fileDate = datetime.datetime.strptime(fileDate,'%b %d, %Y')
			# Get size
			try:
				filePage = urllib2.urlopen(url+pathFile).read()
			except:
				sys.exit('[x] Connection error while getting file page "'+url+pathFile+'"')
			size = re.findall(dumbReSize, filePage)
			if len(size) != 1:
				sys.exit('[x] Error while getting size of "'+pathFile+'"')
			size = int(size[0])
			filesInfoDic[pathFile] = [size, fileDate]
	if dirs != [] and len(dirs) > 1:
		for dir in dirs:
			if dir != 'trunk':
				dirFilesInfo = getRepFilesInfo(url+path, dir+'/')
				if dirFilesInfo != {}:
					for dirFile in dirFilesInfo:
						filesInfoDic[dirFile] = dirFilesInfo[dirFile]
	print '[+] Done'
	return filesInfoDic

def getLocalFilesInfo(filesList):
	localFilesInfo = {}
	print '[-] Getting local files information...'
	for path in filesList:
		if os.path.exists(path):
			fileSize = os.path.getsize(path)
			localFilesInfo[path] = fileSize
	print '[+] Done'
	return localFilesInfo

	
author = 'Jose Miguel Esparza' 
email = 'jesparza AT eternal-todo.com'
url = 'http://peepdf.eternal-todo.com'
twitter = '@eternaltodo'
version = '0.1'
revision = '53'   
stats = ''
pdf = None
fileName = None
newLine = os.linesep
vulnsDict = {'/JBIG2Decode':'CVE-2009-0658','mailto':'CVE-2007-5020','Collab.collectEmailInfo':'CVE-2007-5659','util.printf':'CVE-2008-2992','getAnnots':'CVE-2009-1492','getIcon':'CVE-2009-0927','spell.customDictionaryOpen':'CVE-2009-1493','media.newPlayer':'CVE-2009-4324','doc.printSeps':'CVE-2010-4091','/U3D':['CVE-2009-3953','CVE-2009-3959','CVE-2011-2462']}
versionHeader = 'Version: peepdf ' + version + ' r' + revision
peepdfHeader =  versionHeader + newLine +\
               'Author: ' + author + newLine +\
               'E-mail: ' + email + newLine +\
               'Twitter: ' + twitter + newLine +\
               'URL: ' + url + newLine
               
argsParser = optparse.OptionParser(usage='Usage: '+sys.argv[0]+' [options] PDF_file',version=peepdfHeader,description=versionHeader)
argsParser.add_option('-i', '--interactive', action='store_true', dest='isInteractive', default=False, help='Sets console mode.')
argsParser.add_option('-s', '--load-script', action='store', type='string', dest='scriptFile', help='Load the commands stored in the specified file and execute them.')
argsParser.add_option('-f', '--force-mode', action='store_true', dest='isForceMode', default=False, help='Sets force parsing mode to ignore errors.')
argsParser.add_option('-l', '--loose-mode', action='store_true', dest='isLooseMode', default=False, help='Sets loose parsing mode to catch malformed objects.')
argsParser.add_option('-u', '--update', action='store_true', dest='update', default=False, help='Updates peepdf with the latest files from the repository.')
(options, args) = argsParser.parse_args()

if options.update:
	updated = False
	newVersion = ''
	reVersion = 'version = \'(\d\.\d)\'\s*?revision = \'(\d+)\''
	rawURL = 'http://peepdf.googlecode.com/svn/trunk/'
	browseURL = 'http://code.google.com/p/peepdf/source/browse/trunk/'
	repFilesInfo = getRepFilesInfo(browseURL)
	pathNames = repFilesInfo.keys()
	localFilesInfo = getLocalFilesInfo(pathNames)
	print '[-] Checking files...'
	for path in repFilesInfo:
		repInfo = repFilesInfo[path]
		if localFilesInfo.has_key(path):
			# File exists
			repSize = repInfo[0]
			localSize = localFilesInfo[path]
			if repSize != localSize:
				# Downloading
				print '[-] Downloading new version of "'+path+'"...'
				try:
					fileContent = urllib2.urlopen(rawURL+path).read()
				except:
					sys.exit('[x] Connection error while getting file "'+path+'"')
				# Size check
				if len(fileContent) == repSize:
					updated = True
					open(path,'w').write(fileContent)
					print '[+] File updated successfully'
				else:
					sys.exit('[x] Size check failed for file "'+path+'" ('+str(len(fileContent))+' != '+str(repSize)+')!!')
				if path == 'peepdf.py':
					ver = re.findall(reVersion, fileContent)
					if ver != []:
						newVersion = 'v'+ver[0][0]+' r'+ver[0][1]
		else:
			# File does not exist
			# Downloading
			print '[-] Downloading new file "'+path+'"...'
			try:
				fileContent = urllib2.urlopen(rawURL+path).read()
			except:
				sys.exit('[x] Connection error while getting file "'+path+'"')
			index = path.rfind('/')
			if index != -1:
				dirsPath = path[:index]
				if not os.path.exists(dirsPath):
					os.makedirs(dirsPath)
			open(path,'w').write(fileContent)
			print '[+] File updated successfully'
			updated = True
	if updated:
		message = '[+] peepdf updated successfully'
		if newVersion != '':
			message += ' to '+newVersion
		print message
	else:
		print '[+] No updates needed'
		
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
		stats += 'Encrypted: ' + statsDict['Encrypted'] + newLine
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