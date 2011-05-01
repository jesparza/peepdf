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
	peepdf.py
	Initial script to launch the tool
'''

import sys, os
import optparse
from PDFConsole import PDFConsole
from PDFCore import PDFParser
try:
	from spidermonkey import Runtime
	JS_MODULE = True 
except:
	JS_MODULE = False
	
stats = ''
pdf = None
fileName = None
newLine = os.linesep
vulnsDict = {'/JBIG2Decode':'CVE-2009-0658','mailto':'CVE-2007-5020','Collab.collectEmailInfo':'CVE-2007-5659','util.printf':'CVE-2008-2992','getAnnots':'CVE-2009-1492','getIcon':'CVE-2009-0927','spell.customDictionaryOpen':'CVE-2009-1493','media.newPlayer':'CVE-2009-4324'}

argsParser = optparse.OptionParser('Usage: '+sys.argv[0]+' [options] PDF_file')
argsParser.add_option('-i', '--interactive', action='store_true', dest='isInteractive', default=False, help='Sets console mode.')
argsParser.add_option('-f', '--force-mode', action='store_true', dest='isForceMode', default=False, help='Sets force parsing mode to ignore errors.')
argsParser.add_option('-l', '--loose-mode', action='store_true', dest='isLooseMode', default=False, help='Sets loose parsing mode to catch malformed objects.')
argsParser.add_option('-s', '--load-script', action='store', type='string', dest='scriptFile', help='Load the commands stored in the specified file and execute them.')
(options, args) = argsParser.parse_args()

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
						stats += '\t\t' + vuln + ' (' + vulnsDict[vuln] +'): ' + str(vulns[vuln]) + newLine
					else:
						stats += '\t\t' + vuln + ': ' + str(vulns[vuln]) + newLine
			if elements != None:
				for element in elements:
					stats += '\t\t' + element + ': ' + str(elements[element])
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