#!/usr/bin/env python

#
#    peepdf is a tool to analyse and modify PDF files
#    http://peepdf.eternal-todo.com
#    By Jose Miguel Esparza <jesparza AT eternal-todo.com>
#
#    Copyright (C) 2011-2014 Jose Miguel Esparza
#
#    This file is part of peepdf.
#
#        peepdf is free software: you can redistribute it and/or modify
#        it under the terms of the GNU General Public License as published by
#        the Free Software Foundation, either version 3 of the License, or
#        (at your option) any later version.
#
#        peepdf is distributed in the hope that it will be useful,
#        but WITHOUT ANY WARRANTY; without even the implied warranty of
#        MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.    See the
#        GNU General Public License for more details.
#
#        You should have received a copy of the GNU General Public License
#        along with peepdf.    If not, see <http://www.gnu.org/licenses/>.
#

'''
    Initial script to launch the tool
'''

import sys, os, optparse, re, urllib2, datetime, hashlib, traceback
from datetime import datetime
from PDFCore import PDFParser, vulnsDict
from PDFUtils import vtcheck

VT_KEY = 'fc90df3f5ac749a94a94cb8bf87e05a681a2eb001aef34b6a0084b8c22c97a64'

try:
    import PyV8
    JS_MODULE = True 
except:
    JS_MODULE = False
try:
    import pylibemu
    EMU_MODULE = True 
except:
    EMU_MODULE = False
try:
    from colorama import init, Fore, Back, Style
    COLORIZED_OUTPUT = True
except:
    COLORIZED_OUTPUT = False

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
            content = open(path,'rb').read()
            shaHash = hashlib.sha256(content).hexdigest()
            localFilesInfo[path] = shaHash
    print '[+] Done'
    return localFilesInfo

def getPeepXML(statsDict, version, revision):
    root = etree.Element('peepdf_analysis', version = version+' r'+revision, url = 'http://peepdf.eternal-todo.com', author = 'Jose Miguel Esparza')
    analysisDate = etree.SubElement(root, 'date')
    analysisDate.text = datetime.today().strftime('%Y-%m-%d %H:%M')
    basicInfo = etree.SubElement(root, 'basic')
    fileName = etree.SubElement(basicInfo, 'filename')
    fileName.text = statsDict['File']
    md5 = etree.SubElement(basicInfo, 'md5')
    md5.text = statsDict['MD5']
    sha1 = etree.SubElement(basicInfo, 'sha1')
    sha1.text = statsDict['SHA1']
    sha256 = etree.SubElement(basicInfo, 'sha256')
    sha256.text = statsDict['SHA256']
    size = etree.SubElement(basicInfo, 'size')
    size.text = statsDict['Size']
    detection = etree.SubElement(basicInfo, 'detection')
    if statsDict['Detection'] != [] and statsDict['Detection'] != None:
        detectionRate = etree.SubElement(detection, 'rate')
        detectionRate.text = '%d/%d' % (statsDict['Detection'][0], statsDict['Detection'][1])
        detectionReport = etree.SubElement(detection, 'report_link')
        detectionReport.text = statsDict['Detection report']
    version = etree.SubElement(basicInfo, 'pdf_version')
    version.text = statsDict['Version']
    binary = etree.SubElement(basicInfo, 'binary', status = statsDict['Binary'].lower())
    linearized = etree.SubElement(basicInfo, 'linearized', status = statsDict['Linearized'].lower())
    encrypted = etree.SubElement(basicInfo, 'encrypted', status = statsDict['Encrypted'].lower())
    if statsDict['Encryption Algorithms'] != []:
        algorithms = etree.SubElement(encrypted, 'algorithms')
        for algorithmInfo in statsDict['Encryption Algorithms']:
            algorithm = etree.SubElement(algorithms, 'algorithm', bits = str(algorithmInfo[1]))
            algorithm.text = algorithmInfo[0]
    updates = etree.SubElement(basicInfo, 'updates')
    updates.text = statsDict['Updates']
    objects = etree.SubElement(basicInfo, 'num_objects')
    objects.text = statsDict['Objects']
    streams = etree.SubElement(basicInfo, 'num_streams')
    streams.text = statsDict['Streams']
    comments = etree.SubElement(basicInfo, 'comments')
    comments.text = statsDict['Comments']
    errors = etree.SubElement(basicInfo, 'errors', num = str(len(statsDict['Errors'])))
    for error in statsDict['Errors']:
        errorMessageXML = etree.SubElement(errors, 'error_message')
        errorMessageXML.text = error
    advancedInfo = etree.SubElement(root, 'advanced')
    for version in range(len(statsDict['Versions'])):
        statsVersion = statsDict['Versions'][version]
        if version == 0:
            versionType = 'original'
        else:
            versionType = 'update'
        versionInfo = etree.SubElement(advancedInfo, 'version', num = str(version), type = versionType)
        catalog = etree.SubElement(versionInfo, 'catalog')
        if statsVersion['Catalog'] != None:
            catalog.set('object_id', statsVersion['Catalog'])
        info = etree.SubElement(versionInfo, 'info')
        if statsVersion['Info'] != None:
            info.set('object_id', statsVersion['Info'])
        objects = etree.SubElement(versionInfo, 'objects', num = statsVersion['Objects'][0])
        for id in statsVersion['Objects'][1]:
            object = etree.SubElement(objects, 'object', id = str(id))
            if statsVersion['Compressed Objects'] != None:
                if id in statsVersion['Compressed Objects'][1]:
                    object.set('compressed','true')
                else:
                    object.set('compressed','false')
            if statsVersion['Errors'] != None:
                if id in statsVersion['Errors'][1]:
                    object.set('errors','true')
                else:
                    object.set('errors','false')
        streams = etree.SubElement(versionInfo, 'streams', num = statsVersion['Streams'][0])
        for id in statsVersion['Streams'][1]:
            stream = etree.SubElement(streams, 'stream', id = str(id))
            if statsVersion['Xref Streams'] != None:
                if id in statsVersion['Xref Streams'][1]:
                    stream.set('xref_stream','true')
                else:
                    stream.set('xref_stream','false')
            if statsVersion['Object Streams'] != None:
                if id in statsVersion['Object Streams'][1]:
                    stream.set('object_stream','true')
                else:
                    stream.set('object_stream','false')
            if statsVersion['Encoded'] != None:
                if id in statsVersion['Encoded'][1]:
                    stream.set('encoded','true')
                    if statsVersion['Decoding Errors'] != None:
                        if id in statsVersion['Decoding Errors'][1]:
                            stream.set('decoding_errors','true')
                        else:
                            stream.set('decoding_errors','false')
                else:
                    stream.set('encoded','false')
        jsObjects = etree.SubElement(versionInfo, 'js_objects')
        if statsVersion['Objects with JS code'] != None:
            for id in statsVersion['Objects with JS code'][1]:
                etree.SubElement(jsObjects, 'container_object', id = str(id))
        actions = statsVersion['Actions']
        events = statsVersion['Events']
        vulns = statsVersion['Vulns']
        elements = statsVersion['Elements']
        suspicious = etree.SubElement(versionInfo, 'suspicious_elements')
        if events != None or actions != None or vulns != None or elements != None:
            if events != None:
                triggers = etree.SubElement(suspicious, 'triggers')
                for event in events:
                    trigger = etree.SubElement(triggers, 'trigger', name = event)
                    for id in events[event]:
                        etree.SubElement(trigger, 'container_object', id = str(id))
            if actions != None:
                actionsList = etree.SubElement(suspicious, 'actions')
                for action in actions:
                    actionInfo = etree.SubElement(actionsList, 'action', name = action)
                    for id in actions[action]:
                        etree.SubElement(actionInfo, 'container_object', id = str(id))
            if elements != None:
                elementsList = etree.SubElement(suspicious, 'elements')
                for element in elements:
                    elementInfo = etree.SubElement(elementsList, 'element', name = element)
                    if vulnsDict.has_key(element):
                        for vulnCVE in vulnsDict[element]:
                            cve = etree.SubElement(elementInfo, 'cve')
                            cve.text = vulnCVE
                    for id in elements[element]:
                        etree.SubElement(elementInfo, 'container_object', id = str(id))
            if vulns != None:
                vulnsList = etree.SubElement(suspicious, 'js_vulns')
                for vuln in vulns:
                    vulnInfo = etree.SubElement(vulnsList, 'vulnerable_function', name = vuln)
                    if vulnsDict.has_key(vuln):
                        for vulnCVE in vulnsDict[vuln]:
                            cve = etree.SubElement(vulnInfo, 'cve')
                            cve.text = vulnCVE
                    for id in vulns[vuln]:
                        etree.SubElement(vulnInfo, 'container_object', id = str(id))
        urls = statsVersion['URLs']
        suspiciousURLs = etree.SubElement(versionInfo, 'suspicious_urls')
        if urls != None:
            for url in urls:
                urlInfo = etree.SubElement(versionInfo, 'url')
                urlInfo.text = url
    return etree.tostring(root, pretty_print=True)

    
author = 'Jose Miguel Esparza' 
email = 'peepdf AT eternal-todo.com'
url = 'http://peepdf.eternal-todo.com'
twitter = 'http://twitter.com/EternalTodo'
peepTwitter = 'http://twitter.com/peepdf'
version = '0.2'
revision = '229'   
stats = ''
pdf = None
fileName = None
statsDict = None
vtJsonDict = None
newLine = os.linesep
errorsFile = 'errors.txt'

versionHeader = 'Version: peepdf ' + version + ' r' + revision
peepdfHeader =  versionHeader + newLine*2 +\
               url + newLine +\
               peepTwitter + newLine +\
               email + newLine*2 +\
               author + newLine +\
               twitter + newLine

argsParser = optparse.OptionParser(usage='Usage: '+sys.argv[0]+' [options] PDF_file',description=versionHeader)
argsParser.add_option('-i', '--interactive', action='store_true', dest='isInteractive', default=False, help='Sets console mode.')
argsParser.add_option('-s', '--load-script', action='store', type='string', dest='scriptFile', help='Loads the commands stored in the specified file and execute them.')
argsParser.add_option('-c', '--check-vt', action='store_true', dest='checkOnVT', default=False, help='Checks the hash of the PDF file on VirusTotal.')
argsParser.add_option('-f', '--force-mode', action='store_true', dest='isForceMode', default=False, help='Sets force parsing mode to ignore errors.')
argsParser.add_option('-l', '--loose-mode', action='store_true', dest='isLooseMode', default=False, help='Sets loose parsing mode to catch malformed objects.')
argsParser.add_option('-m', '--manual-analysis', action='store_true', dest='isManualAnalysis', default=False, help='Avoids automatic Javascript analysis. Useful with eternal loops like heap spraying.')
argsParser.add_option('-u', '--update', action='store_true', dest='update', default=False, help='Updates peepdf with the latest files from the repository.')
argsParser.add_option('-g', '--grinch-mode', action='store_true', dest='avoidColors', default=False, help='Avoids colorized output in the interactive console.')
argsParser.add_option('-v', '--version', action='store_true', dest='version', default=False, help='Shows program\'s version number.')
argsParser.add_option('-x', '--xml', action='store_true', dest='xmlOutput', default=False, help='Shows the document information in XML format.')
(options, args) = argsParser.parse_args()

try:
    # Avoid colors in the output
    if not COLORIZED_OUTPUT or options.avoidColors:
        warningColor = ''
        errorColor = ''
        alertColor = ''
        staticColor = ''
        resetColor = ''
    else:
        warningColor = Fore.YELLOW
        errorColor = Fore.RED
        alertColor = Fore.RED
        staticColor = Fore.BLUE
        resetColor = Style.RESET_ALL
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
            sys.exit('[x] Connection error while trying to connect with the repository')
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
                        open(path,'wb').write(fileContent)
                        print '[+] File "'+path+'" updated successfully'
                else:
                    # File does not exist
                    index = path.rfind('/')
                    if index != -1:
                        dirsPath = path[:index]
                        if not os.path.exists(dirsPath):
                            print '[+] New directory "'+dirsPath+'" created successfully'
                            os.makedirs(dirsPath)
                    open(path,'wb').write(fileContent)
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
            pdfParser = PDFParser()
            ret,pdf = pdfParser.parse(fileName, options.isForceMode, options.isLooseMode, options.isManualAnalysis)
            if options.checkOnVT:
                # Checks the MD5 on VirusTotal
                md5Hash = pdf.getMD5()
                ret = vtcheck(md5Hash, VT_KEY)
                if ret[0] == -1:
                    pdf.addError(ret[1])
                else:
                    vtJsonDict = ret[1]
                    if vtJsonDict.has_key('response_code'):
                        if vtJsonDict['response_code'] == 1:
                            if vtJsonDict.has_key('positives') and vtJsonDict.has_key('total'):
                                pdf.setDetectionRate([vtJsonDict['positives'], vtJsonDict['total']])
                            else:
                                pdf.addError('Missing elements in the response from VirusTotal!!')
                            if vtJsonDict.has_key('permalink'):
                                pdf.setDetectionReport(vtJsonDict['permalink'])
                        else:
                            pdf.setDetectionRate(None)
                    else:
                        pdf.addError('Bad response from VirusTotal!!')
            statsDict = pdf.getStats()
        
        if options.xmlOutput:
            try:
                from lxml import etree
                xml = getPeepXML(statsDict, version, revision)
                sys.stdout.write(xml)
            except:
                errorMessage = '*** Error: Exception while generating the XML file!!'
                traceback.print_exc(file=open(errorsFile,'a'))
                raise Exception('PeepException','Send me an email ;)')    
        else:
            if COLORIZED_OUTPUT and not options.avoidColors:
                try:
                    init()
                except:
                    COLORIZED_OUTPUT = False
            if options.scriptFile != None:
                from PDFConsole import PDFConsole
                scriptFileObject = open(options.scriptFile,'rb')
                console = PDFConsole(pdf, VT_KEY, options.avoidColors, stdin=scriptFileObject)
                try:
                    console.cmdloop()
                except:
                    errorMessage = '*** Error: Exception not handled using the batch mode!!'
                    scriptFileObject.close()
                    traceback.print_exc(file=open(errorsFile,'a'))
                    raise Exception('PeepException','Send me an email ;)') 
            else:
                if statsDict != None:
                    if COLORIZED_OUTPUT and not options.avoidColors:
                        beforeStaticLabel = staticColor
                    else:
                        beforeStaticLabel = ''

                    if not JS_MODULE:
                        warningMessage = 'Warning: PyV8 is not installed!!'
                        stats += warningColor + warningMessage + resetColor + newLine
                    if not EMU_MODULE:
                        warningMessage = 'Warning: pylibemu is not installed!!'
                        stats += warningColor + warningMessage + resetColor + newLine
                    errors = statsDict['Errors']
                    for error in errors:
                        if error.find('Decryption error') != -1:
                            stats += errorColor + error + resetColor + newLine
                    if stats != '':
                        stats += newLine
                    statsDict = pdf.getStats()
                                                    
                    stats += beforeStaticLabel + 'File: ' + resetColor + statsDict['File'] + newLine
                    stats += beforeStaticLabel + 'MD5: ' + resetColor + statsDict['MD5'] + newLine
                    stats += beforeStaticLabel + 'SHA1: ' + resetColor + statsDict['SHA1'] + newLine
                    #stats += beforeStaticLabel + 'SHA256: ' + resetColor + statsDict['SHA256'] + newLine
                    stats += beforeStaticLabel + 'Size: ' + resetColor + statsDict['Size'] + ' bytes' + newLine
                    if options.checkOnVT:
                        if statsDict['Detection'] != []:
                            detectionReportInfo = ''
                            if statsDict['Detection'] != None:
                                 detectionColor = ''
                                 if COLORIZED_OUTPUT and not options.avoidColors:
                                	 detectionLevel = statsDict['Detection'][0]/(statsDict['Detection'][1]/3)
                                	 if detectionLevel == 0:
                                	 	 detectionColor = alertColor
                                	 elif detectionLevel == 1:
                                	 	 detectionColor = warningColor  
                                 detectionRate = '%s%d%s/%d' % (detectionColor, statsDict['Detection'][0], resetColor, statsDict['Detection'][1])
                                 if statsDict['Detection report'] != '':
                                     detectionReportInfo = beforeStaticLabel + 'Detection report: ' + resetColor + statsDict['Detection report'] + newLine
                            else:
								 detectionRate = 'File not found on VirusTotal'
                            stats += beforeStaticLabel + 'Detection: ' + resetColor + detectionRate + newLine
                            stats += detectionReportInfo
                    stats += beforeStaticLabel + 'Version: ' + resetColor + statsDict['Version'] + newLine
                    stats += beforeStaticLabel + 'Binary: ' + resetColor + statsDict['Binary'] + newLine
                    stats += beforeStaticLabel + 'Linearized: ' + resetColor + statsDict['Linearized'] + newLine
                    stats += beforeStaticLabel + 'Encrypted: ' + resetColor + statsDict['Encrypted']
                    if statsDict['Encryption Algorithms'] != []:
                        stats += ' ('
                        for algorithmInfo in statsDict['Encryption Algorithms']:
                            stats += algorithmInfo[0] + ' ' + str(algorithmInfo[1]) + ' bits, '
                        stats = stats[:-2] + ')'
                    stats += newLine
                    stats += beforeStaticLabel + 'Updates: ' + resetColor + statsDict['Updates'] + newLine
                    stats += beforeStaticLabel + 'Objects: ' + resetColor + statsDict['Objects'] + newLine
                    stats += beforeStaticLabel + 'Streams: ' + resetColor + statsDict['Streams'] + newLine
                    stats += beforeStaticLabel + 'Comments: ' + resetColor + statsDict['Comments'] + newLine
                    stats += beforeStaticLabel + 'Errors: ' + resetColor + str(len(statsDict['Errors'])) + newLine*2                    
                    for version in range(len(statsDict['Versions'])):
                        statsVersion = statsDict['Versions'][version]
                        stats += beforeStaticLabel + 'Version ' + resetColor + str(version) + ':' + newLine
                        if statsVersion['Catalog'] != None:
                            stats += beforeStaticLabel + '\tCatalog: ' + resetColor + statsVersion['Catalog'] + newLine
                        else:
                            stats += beforeStaticLabel + '\tCatalog: ' + resetColor + 'No' + newLine
                        if statsVersion['Info'] != None:
                            stats += beforeStaticLabel + '\tInfo: ' + resetColor + statsVersion['Info'] + newLine
                        else:
                            stats += beforeStaticLabel + '\tInfo: ' + resetColor + 'No' + newLine
                        stats += beforeStaticLabel + '\tObjects ('+statsVersion['Objects'][0]+'): ' + resetColor + str(statsVersion['Objects'][1]) + newLine
                        if statsVersion['Compressed Objects'] != None:
                            stats += beforeStaticLabel + '\tCompressed objects ('+statsVersion['Compressed Objects'][0]+'): ' + resetColor + str(statsVersion['Compressed Objects'][1]) + newLine
                        if statsVersion['Errors'] != None:
                            stats += beforeStaticLabel + '\t\tErrors ('+statsVersion['Errors'][0]+'): ' + resetColor + str(statsVersion['Errors'][1]) + newLine
                        stats += beforeStaticLabel + '\tStreams ('+statsVersion['Streams'][0]+'): ' + resetColor + str(statsVersion['Streams'][1])
                        if statsVersion['Xref Streams'] != None:
                            stats += newLine + beforeStaticLabel + '\t\tXref streams ('+statsVersion['Xref Streams'][0]+'): ' + resetColor + str(statsVersion['Xref Streams'][1])
                        if statsVersion['Object Streams'] != None:
                            stats += newLine + beforeStaticLabel + '\t\tObject streams ('+statsVersion['Object Streams'][0]+'): ' + resetColor + str(statsVersion['Object Streams'][1])
                        if int(statsVersion['Streams'][0]) > 0:
                            stats += newLine + beforeStaticLabel + '\t\tEncoded ('+statsVersion['Encoded'][0]+'): ' + resetColor + str(statsVersion['Encoded'][1])
                            if statsVersion['Decoding Errors'] != None:
                                stats += newLine + beforeStaticLabel + '\t\tDecoding errors ('+statsVersion['Decoding Errors'][0]+'): ' + resetColor + str(statsVersion['Decoding Errors'][1])
                        if COLORIZED_OUTPUT and not options.avoidColors:
                            beforeStaticLabel = warningColor
                        if statsVersion['Objects with JS code'] != None:
                            stats += newLine + beforeStaticLabel + '\tObjects with JS code ('+statsVersion['Objects with JS code'][0]+'): ' + resetColor + str(statsVersion['Objects with JS code'][1])
                        actions = statsVersion['Actions']
                        events = statsVersion['Events']
                        vulns = statsVersion['Vulns']
                        elements = statsVersion['Elements']
                        if events != None or actions != None or vulns != None or elements != None:
                            stats += newLine + beforeStaticLabel + '\tSuspicious elements:' + resetColor + newLine
                            if events != None:
                                for event in events:
                                    stats += '\t\t' + beforeStaticLabel + event + ': ' + resetColor + str(events[event]) + newLine
                            if actions != None:
                                for action in actions:
                                    stats += '\t\t' + beforeStaticLabel + action + ': ' + resetColor + str(actions[action]) + newLine
                            if vulns != None:
                                for vuln in vulns:
                                    if vulnsDict.has_key(vuln):
                                        stats += '\t\t' + beforeStaticLabel + vuln + ' ('
                                        for vulnCVE in vulnsDict[vuln]: 
                                            stats += vulnCVE + ',' 
                                        stats = stats[:-1] + '): ' + resetColor + str(vulns[vuln]) + newLine
                                    else:
                                        stats += '\t\t' + beforeStaticLabel + vuln + ': ' + resetColor + str(vulns[vuln]) + newLine
                            if elements != None:
                                for element in elements:
                                    if vulnsDict.has_key(element):
                                        stats += '\t\t' + beforeStaticLabel + element + ' ('
                                        for vulnCVE in vulnsDict[element]: 
                                            stats += vulnCVE + ',' 
                                        stats = stats[:-1] + '): ' + resetColor + str(elements[element]) + newLine
                                    else:
                                        stats += '\t\t' + beforeStaticLabel + element + ': ' + resetColor + str(elements[element]) + newLine
                        if COLORIZED_OUTPUT and not options.avoidColors:
                            beforeStaticLabel = staticColor
                        urls = statsVersion['URLs']
                        if urls != None:
                            stats += newLine + beforeStaticLabel + '\tFound URLs:' + resetColor + newLine
                            for url in urls:
                                stats += '\t\t' + url + newLine
                        stats += newLine * 2
                if fileName != None:
                    print stats
                if options.isInteractive:
                    from PDFConsole import PDFConsole
                    console = PDFConsole(pdf, VT_KEY, options.avoidColors)
                    while not console.leaving:
                        try:
                            console.cmdloop()
                        except:
                            errorMessage = '*** Error: Exception not handled using the interactive console!! Please, report it to the author!!'
                            print errorColor + errorMessage + resetColor + newLine
                            traceback.print_exc(file=open(errorsFile,'a'))
except Exception as e:
    if len(e.args) == 2:
        excName,excReason = e.args
    else:
        excName = excReason = None
    if excName == None or excName != 'PeepException':
        errorMessage = '*** Error: Exception not handled!!'
        traceback.print_exc(file=open(errorsFile,'a'))
    print errorColor + errorMessage + resetColor + newLine
finally:
    if os.path.exists(errorsFile):
        message = newLine + 'Please, don\'t forget to report the errors found:' + newLine*2 
        message += '\t- Sending the file "errors.txt" to the author (mailto:peepdfREMOVETHIS@eternal-todo.com)"' + newLine
        message += '\t- And/Or creating an issue on the project webpage (https://code.google.com/p/peepdf/issues/list)' + newLine
        message = errorColor + message + resetColor
        sys.exit(message)