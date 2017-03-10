#!/usr/bin/env python

#
# peepdf is a tool to analyse and modify PDF files
#    http://peepdf.eternal-todo.com
#    By Jose Miguel Esparza <jesparza AT eternal-todo.com>
#
#    Copyright (C) 2011-2017 Jose Miguel Esparza
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

import sys
import os
import optparse
import traceback
import json
from datetime import datetime
from peepdf.PDFCore import PDFParser, vulnsDict
from peepdf.PDFUtils import vtcheck


VT_KEY = 'fc90df3f5ac749a94a94cb8bf87e05a681a2eb001aef34b6a0084b8c22c97a64'

try:
    import PyV8
    JS_MODULE = True

    PyV8
except:
    JS_MODULE = False
try:
    import pylibemu
    EMU_MODULE = True

    pylibemu
except:
    EMU_MODULE = False
try:
    from colorama import init, Fore, Style
    COLORIZED_OUTPUT = True
except:
    COLORIZED_OUTPUT = False

try:
    from PIL import Image
    PIL_MODULE = True

    Image
except:
    PIL_MODULE = False


try:
    from lxml import etree
except:
    etree = None


def getPeepXML(statsDict, version, revision):
    assert etree is not None, "lxml must be installed for --xml"

    root = etree.Element('peepdf_analysis', version=version + ' r' + revision, url='http://peepdf.eternal-todo.com',
                         author='Jose Miguel Esparza')
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
    if statsDict['Detection']:
        detectionRate = etree.SubElement(detection, 'rate')
        detectionRate.text = '%d/%d' % (statsDict['Detection'][0], statsDict['Detection'][1])
        detectionReport = etree.SubElement(detection, 'report_link')
        detectionReport.text = statsDict['Detection report']
    version = etree.SubElement(basicInfo, 'pdf_version')
    version.text = statsDict['Version']
    encrypted = etree.SubElement(basicInfo, 'encrypted', status=statsDict['Encrypted'].lower())
    if statsDict['Encryption Algorithms']:
        algorithms = etree.SubElement(encrypted, 'algorithms')
        for algorithmInfo in statsDict['Encryption Algorithms']:
            algorithm = etree.SubElement(algorithms, 'algorithm', bits=str(algorithmInfo[1]))
            algorithm.text = algorithmInfo[0]
    updates = etree.SubElement(basicInfo, 'updates')
    updates.text = statsDict['Updates']
    objects = etree.SubElement(basicInfo, 'num_objects')
    objects.text = statsDict['Objects']
    streams = etree.SubElement(basicInfo, 'num_streams')
    streams.text = statsDict['Streams']
    comments = etree.SubElement(basicInfo, 'comments')
    comments.text = statsDict['Comments']
    errors = etree.SubElement(basicInfo, 'errors', num=str(len(statsDict['Errors'])))
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
        versionInfo = etree.SubElement(advancedInfo, 'version', num=str(version), type=versionType)
        catalog = etree.SubElement(versionInfo, 'catalog')
        if statsVersion['Catalog'] is not None:
            catalog.set('object_id', statsVersion['Catalog'])
        info = etree.SubElement(versionInfo, 'info')
        if statsVersion['Info'] is not None:
            info.set('object_id', statsVersion['Info'])
        objects = etree.SubElement(versionInfo, 'objects', num=statsVersion['Objects'][0])
        for id in statsVersion['Objects'][1]:
            object = etree.SubElement(objects, 'object', id=str(id))
            if statsVersion['Compressed Objects'] is not None:
                if id in statsVersion['Compressed Objects'][1]:
                    object.set('compressed', 'true')
                else:
                    object.set('compressed', 'false')
            if statsVersion['Errors'] is not None:
                if id in statsVersion['Errors'][1]:
                    object.set('errors', 'true')
                else:
                    object.set('errors', 'false')
        streams = etree.SubElement(versionInfo, 'streams', num=statsVersion['Streams'][0])
        for id in statsVersion['Streams'][1]:
            stream = etree.SubElement(streams, 'stream', id=str(id))
            if statsVersion['Xref Streams'] is not None:
                if id in statsVersion['Xref Streams'][1]:
                    stream.set('xref_stream', 'true')
                else:
                    stream.set('xref_stream', 'false')
            if statsVersion['Object Streams'] is not None:
                if id in statsVersion['Object Streams'][1]:
                    stream.set('object_stream', 'true')
                else:
                    stream.set('object_stream', 'false')
            if statsVersion['Encoded'] is not None:
                if id in statsVersion['Encoded'][1]:
                    stream.set('encoded', 'true')
                    if statsVersion['Decoding Errors'] is not None:
                        if id in statsVersion['Decoding Errors'][1]:
                            stream.set('decoding_errors', 'true')
                        else:
                            stream.set('decoding_errors', 'false')
                else:
                    stream.set('encoded', 'false')
        jsObjects = etree.SubElement(versionInfo, 'js_objects')
        if statsVersion['Objects with JS code'] is not None:
            for id in statsVersion['Objects with JS code'][1]:
                etree.SubElement(jsObjects, 'container_object', id=str(id))
        actions = statsVersion['Actions']
        events = statsVersion['Events']
        vulns = statsVersion['Vulns']
        elements = statsVersion['Elements']
        suspicious = etree.SubElement(versionInfo, 'suspicious_elements')
        if events is not None or actions is not None or vulns is not None or elements is not None:
            if events:
                triggers = etree.SubElement(suspicious, 'triggers')
                for event in events:
                    trigger = etree.SubElement(triggers, 'trigger', name=event)
                    for id in events[event]:
                        etree.SubElement(trigger, 'container_object', id=str(id))
            if actions:
                actionsList = etree.SubElement(suspicious, 'actions')
                for action in actions:
                    actionInfo = etree.SubElement(actionsList, 'action', name=action)
                    for id in actions[action]:
                        etree.SubElement(actionInfo, 'container_object', id=str(id))
            if elements:
                elementsList = etree.SubElement(suspicious, 'elements')
                for element in elements:
                    elementInfo = etree.SubElement(elementsList, 'element', name=element)
                    if element in vulnsDict:
                        vulnCVEList = vulnsDict[element][1]
                        for vulnCVE in vulnCVEList:
                            cve = etree.SubElement(elementInfo, 'cve')
                            cve.text = vulnCVE
                    for id in elements[element]:
                        etree.SubElement(elementInfo, 'container_object', id=str(id))
            if vulns:
                vulnsList = etree.SubElement(suspicious, 'js_vulns')
                for vuln in vulns:
                    vulnInfo = etree.SubElement(vulnsList, 'vulnerable_function', name=vuln)
                    if vuln in vulnsDict:
                        vulnCVEList = vulnsDict[vuln][1]
                        for vulnCVE in vulnCVEList:
                            cve = etree.SubElement(vulnInfo, 'cve')
                            cve.text = vulnCVE
                    for id in vulns[vuln]:
                        etree.SubElement(vulnInfo, 'container_object', id=str(id))
        urls = statsVersion['URLs']
        suspiciousURLs = etree.SubElement(versionInfo, 'suspicious_urls')
        if urls is not None:
            for url in urls:
                urlInfo = etree.SubElement(suspiciousURLs, 'url')
                urlInfo.text = url
    return etree.tostring(root, pretty_print=True)


def getPeepJSON(statsDict, version, revision):
    # peepdf info
    peepdfDict = {'version': version,
                  'revision': revision,
                  'author': 'Jose Miguel Esparza',
                  'url': 'http://peepdf.eternal-todo.com'}
    # Basic info
    basicDict = {}
    basicDict['filename'] = statsDict['File']
    basicDict['md5'] = statsDict['MD5']
    basicDict['sha1'] = statsDict['SHA1']
    basicDict['sha256'] = statsDict['SHA256']
    basicDict['size'] = int(statsDict['Size'])
    basicDict['detection'] = {}
    if statsDict['Detection'] != [] and statsDict['Detection'] is not None:
        basicDict['detection']['rate'] = '%d/%d' % (statsDict['Detection'][0], statsDict['Detection'][1])
        basicDict['detection']['report_link'] = statsDict['Detection report']
    basicDict['pdf_version'] = statsDict['Version']
    basicDict['binary'] = bool(statsDict['Binary'])
    basicDict['linearized'] = bool(statsDict['Linearized'])
    basicDict['encrypted'] = bool(statsDict['Encrypted'])
    basicDict['encryption_algorithms'] = []
    if statsDict['Encryption Algorithms']:
        for algorithmInfo in statsDict['Encryption Algorithms']:
            basicDict['encryption_algorithms'].append({'bits': algorithmInfo[1], 'algorithm': algorithmInfo[0]})
    basicDict['updates'] = int(statsDict['Updates'])
    basicDict['num_objects'] = int(statsDict['Objects'])
    basicDict['num_streams'] = int(statsDict['Streams'])
    basicDict['comments'] = int(statsDict['Comments'])
    basicDict['errors'] = []
    for error in statsDict['Errors']:
        basicDict['errors'].append(error)
    # Advanced info
    advancedInfo = []
    for version in range(len(statsDict['Versions'])):
        statsVersion = statsDict['Versions'][version]
        if version == 0:
            versionType = 'original'
        else:
            versionType = 'update'
        versionInfo = {}
        versionInfo['version_number'] = version
        versionInfo['version_type'] = versionType
        versionInfo['catalog'] = statsVersion['Catalog']
        versionInfo['info'] = statsVersion['Info']
        if statsVersion['Objects'] is not None:
            versionInfo['objects'] = statsVersion['Objects'][1]
        else:
            versionInfo['objects'] = []
        if statsVersion['Compressed Objects'] is not None:
            versionInfo['compressed_objects'] = statsVersion['Compressed Objects'][1]
        else:
            versionInfo['compressed_objects'] = []
        if statsVersion['Errors'] is not None:
            versionInfo['error_objects'] = statsVersion['Errors'][1]
        else:
            versionInfo['error_objects'] = []
        if statsVersion['Streams'] is not None:
            versionInfo['streams'] = statsVersion['Streams'][1]
        else:
            versionInfo['streams'] = []
        if statsVersion['Xref Streams'] is not None:
            versionInfo['xref_streams'] = statsVersion['Xref Streams'][1]
        else:
            versionInfo['xref_streams'] = []
        if statsVersion['Encoded'] is not None:
            versionInfo['encoded_streams'] = statsVersion['Encoded'][1]
        else:
            versionInfo['encoded_streams'] = []
        if versionInfo['encoded_streams'] and statsVersion['Decoding Errors'] is not None:
            versionInfo['decoding_error_streams'] = statsVersion['Decoding Errors'][1]
        else:
            versionInfo['decoding_error_streams'] = []
        if statsVersion['Objects with JS code'] is not None:
            versionInfo['js_objects'] = statsVersion['Objects with JS code'][1]
        else:
            versionInfo['js_objects'] = []
        elements = statsVersion['Elements']
        elementArray = []
        if elements:
            for element in elements:
                elementInfo = {'name': element}
                if element in vulnsDict:
                    elementInfo['vuln_name'] = vulnsDict[element][0]
                    elementInfo['vuln_cve_list'] = vulnsDict[element][1]
                elementInfo['objects'] = elements[element]
                elementArray.append(elementInfo)
        vulns = statsVersion['Vulns']
        vulnArray = []
        if vulns:
            for vuln in vulns:
                vulnInfo = {'name': vuln}
                if vuln in vulnsDict:
                    vulnInfo['vuln_name'] = vulnsDict[vuln][0]
                    vulnInfo['vuln_cve_list'] = vulnsDict[vuln][1]
                vulnInfo['objects'] = vulns[vuln]
                vulnArray.append(vulnInfo)
        versionInfo['suspicious_elements'] = {'triggers': statsVersion['Events'],
                                              'actions': statsVersion['Actions'],
                                              'elements': elementArray,
                                              'js_vulns': vulnArray,
                                              'urls': statsVersion['URLs']}
        versionReport = {'version_info': versionInfo}
        advancedInfo.append(versionReport)
    jsonDict = {
        'peepdf_analysis': {
            'peepdf_info': peepdfDict,
            'date': datetime.today().strftime('%Y-%m-%d %H:%M'),
            'basic': basicDict,
            'advanced': advancedInfo,
        }
    }
    return json.dumps(jsonDict, indent=4, sort_keys=True)


author = 'Jose Miguel Esparza'
email = 'peepdf AT eternal-todo.com'
url = 'http://peepdf.eternal-todo.com'
twitter = 'http://twitter.com/EternalTodo'
peepTwitter = 'http://twitter.com/peepdf'
_version = '0.3'
revision = '275'
newLine = os.linesep
errorsFile = os.path.expanduser("~/.peepdf-error.txt")

versionHeader = 'Version: peepdf ' + _version + ' r' + revision
peepdfHeader = (
    versionHeader + newLine * 2 + url + newLine + peepTwitter + newLine +
    email + newLine * 2 + author + newLine + twitter + newLine
)

def main():
    global COLORIZED_OUTPUT

    argsParser = optparse.OptionParser(usage='Usage: peepdf.py [options] PDF_file', description=versionHeader)
    argsParser.add_option('-i', '--interactive', action='store_true', dest='isInteractive', default=False, help='Sets console mode.')
    argsParser.add_option('-s', '--load-script', action='store', type='string', dest='scriptFile', help='Loads the commands stored in the specified file and execute them.')
    argsParser.add_option('-c', '--check-vt', action='store_true', dest='checkOnVT', default=False, help='Checks the hash of the PDF file on VirusTotal.')
    argsParser.add_option('-f', '--force-mode', action='store_true', dest='isForceMode', default=False, help='Sets force parsing mode to ignore errors.')
    argsParser.add_option('-l', '--loose-mode', action='store_true', dest='isLooseMode', default=False, help='Sets loose parsing mode to catch malformed objects.')
    argsParser.add_option('-m', '--manual-analysis', action='store_true', dest='isManualAnalysis', default=False, help='Avoids automatic Javascript analysis. Useful with eternal loops like heap spraying.')
    argsParser.add_option('-g', '--grinch-mode', action='store_true', dest='avoidColors', default=False, help='Avoids colorized output in the interactive console.')
    argsParser.add_option('-v', '--version', action='store_true', dest='version', default=False, help='Shows program\'s version number.')
    argsParser.add_option('-x', '--xml', action='store_true', dest='xmlOutput', default=False, help='Shows the document information in XML format.')
    argsParser.add_option('-j', '--json', action='store_true', dest='jsonOutput', default=False, help='Shows the document information in JSON format.')
    argsParser.add_option('-C', '--command', action='append', type='string', dest='commands', help='Specifies a command from the interactive console to be executed.')
    (options, args) = argsParser.parse_args()

    stats = ""
    pdf = None
    fileName = None
    statsDict = None
    vtJsonDict = None

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
        else:
            if len(args) == 1:
                fileName = args[0]
                if not os.path.exists(fileName):
                    sys.exit('Error: The file "' + fileName + '" does not exist!!')
            elif len(args) > 1 or (len(args) == 0 and not options.isInteractive):
                sys.exit(argsParser.print_help())

            if options.scriptFile is not None:
                if not os.path.exists(options.scriptFile):
                    sys.exit('Error: The script file "' + options.scriptFile + '" does not exist!!')

            if fileName is not None:
                pdfParser = PDFParser()
                ret, pdf = pdfParser.parse(fileName, options.isForceMode, options.isLooseMode, options.isManualAnalysis)
                if options.checkOnVT:
                    # Checks the MD5 on VirusTotal
                    md5Hash = pdf.getMD5()
                    ret = vtcheck(md5Hash, VT_KEY)
                    if ret[0] == -1:
                        pdf.addError(ret[1])
                    else:
                        vtJsonDict = ret[1]
                        if "response_code" in vtJsonDict:
                            if vtJsonDict['response_code'] == 1:
                                if "positives" in vtJsonDict and "total" in vtJsonDict:
                                    pdf.setDetectionRate([vtJsonDict['positives'], vtJsonDict['total']])
                                else:
                                    pdf.addError('Missing elements in the response from VirusTotal!!')
                                if "permalink" in vtJsonDict:
                                    pdf.setDetectionReport(vtJsonDict['permalink'])
                            else:
                                pdf.setDetectionRate(None)
                        else:
                            pdf.addError('Bad response from VirusTotal!!')
                statsDict = pdf.getStats()

            if options.xmlOutput:
                try:
                    xml = getPeepXML(statsDict, _version, revision)
                    sys.stdout.write(xml)
                except:
                    errorMessage = '*** Error: Exception while generating the XML file!!'
                    traceback.print_exc(file=open(errorsFile, 'a'))
                    raise Exception('PeepException', 'Send me an email ;)')
            elif options.jsonOutput and not options.commands:
                try:
                    jsonReport = getPeepJSON(statsDict, _version, revision)
                    sys.stdout.write(jsonReport)
                except:
                    errorMessage = '*** Error: Exception while generating the JSON report!!'
                    traceback.print_exc(file=open(errorsFile, 'a'))
                    raise Exception('PeepException', 'Send me an email ;)')
            else:
                if COLORIZED_OUTPUT and not options.avoidColors:
                    try:
                        init()
                    except:
                        COLORIZED_OUTPUT = False
                if options.scriptFile is not None:
                    from peepdf.PDFConsole import PDFConsole

                    scriptFileObject = open(options.scriptFile, 'rb')
                    console = PDFConsole(pdf, VT_KEY, options.avoidColors, stdin=scriptFileObject)
                    try:
                        console.cmdloop()
                    except:
                        errorMessage = '*** Error: Exception not handled using the batch mode!!'
                        scriptFileObject.close()
                        traceback.print_exc(file=open(errorsFile, 'a'))
                        raise Exception('PeepException', 'Send me an email ;)')
                elif options.commands is not None:
                    from PDFConsole import PDFConsole

                    console = PDFConsole(pdf, VT_KEY, options.avoidColors)
                    try:
                        for command in options.commands:
                            console.onecmd(command)
                    except:
                        errorMessage = '*** Error: Exception not handled using the batch commands!!'
                        traceback.print_exc(file=open(errorsFile, 'a'))
                        raise Exception('PeepException', 'Send me an email ;)')
                else:
                    if statsDict is not None:
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
                        if not PIL_MODULE:
                            warningMessage = 'Warning: Python Imaging Library (PIL) is not installed!!'
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
                        stats += beforeStaticLabel + 'SHA256: ' + resetColor + statsDict['SHA256'] + newLine
                        stats += beforeStaticLabel + 'Size: ' + resetColor + statsDict['Size'] + ' bytes' + newLine
                        if options.checkOnVT:
                            if statsDict['Detection'] != []:
                                detectionReportInfo = ''
                                if statsDict['Detection'] is not None:
                                    detectionColor = ''
                                    if COLORIZED_OUTPUT and not options.avoidColors:
                                        detectionLevel = statsDict['Detection'][0] / (statsDict['Detection'][1] / 3)
                                        if detectionLevel == 0:
                                            detectionColor = alertColor
                                        elif detectionLevel == 1:
                                            detectionColor = warningColor
                                    detectionRate = '%s%d%s/%d' % (
                                        detectionColor, statsDict['Detection'][0], resetColor, statsDict['Detection'][1])
                                    if statsDict['Detection report'] != '':
                                        detectionReportInfo = (
                                            beforeStaticLabel + 'Detection report: ' + resetColor +
                                            statsDict['Detection report'] + newLine
                                        )
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
                        stats += beforeStaticLabel + 'URIs: ' + resetColor + statsDict['URIs'] + newLine
                        stats += beforeStaticLabel + 'Comments: ' + resetColor + statsDict['Comments'] + newLine
                        stats += beforeStaticLabel + 'Errors: ' + resetColor + str(len(statsDict['Errors'])) + newLine * 2
                        for version in range(len(statsDict['Versions'])):
                            statsVersion = statsDict['Versions'][version]
                            stats += beforeStaticLabel + 'Version ' + resetColor + str(version) + ':' + newLine
                            if statsVersion['Catalog'] is not None:
                                stats += beforeStaticLabel + '\tCatalog: ' + resetColor + statsVersion['Catalog'] + newLine
                            else:
                                stats += beforeStaticLabel + '\tCatalog: ' + resetColor + 'No' + newLine
                            if statsVersion['Info'] is not None:
                                stats += beforeStaticLabel + '\tInfo: ' + resetColor + statsVersion['Info'] + newLine
                            else:
                                stats += beforeStaticLabel + '\tInfo: ' + resetColor + 'No' + newLine
                            stats += beforeStaticLabel + '\tObjects (' + statsVersion['Objects'][
                                0] + '): ' + resetColor + str(statsVersion['Objects'][1]) + newLine
                            if statsVersion['Compressed Objects'] is not None:
                                stats += beforeStaticLabel + '\tCompressed objects (' + statsVersion['Compressed Objects'][
                                    0] + '): ' + resetColor + str(statsVersion['Compressed Objects'][1]) + newLine
                            if statsVersion['Errors'] is not None:
                                stats += beforeStaticLabel + '\t\tErrors (' + statsVersion['Errors'][
                                    0] + '): ' + resetColor + str(statsVersion['Errors'][1]) + newLine
                            stats += beforeStaticLabel + '\tStreams (' + statsVersion['Streams'][
                                0] + '): ' + resetColor + str(statsVersion['Streams'][1])
                            if statsVersion['Xref Streams'] is not None:
                                stats += newLine + beforeStaticLabel + '\t\tXref streams (' + statsVersion['Xref Streams'][
                                    0] + '): ' + resetColor + str(statsVersion['Xref Streams'][1])
                            if statsVersion['Object Streams'] is not None:
                                stats += (
                                    newLine + beforeStaticLabel + '\t\tObject streams (' +
                                    statsVersion['Object Streams'][0] + '): ' + resetColor +
                                    str(statsVersion['Object Streams'][1])
                                )
                            if int(statsVersion['Streams'][0]) > 0:
                                stats += (
                                    newLine + beforeStaticLabel + '\t\tEncoded (' + statsVersion['Encoded'][0] +
                                    '): ' + resetColor + str(statsVersion['Encoded'][1])
                                )
                                if statsVersion['Decoding Errors'] is not None:
                                    stats += (
                                        newLine + beforeStaticLabel + '\t\tDecoding errors (' +
                                        statsVersion['Decoding Errors'][0] + '): ' + resetColor +
                                        str(statsVersion['Decoding Errors'][1])
                                    )
                            if statsVersion['URIs'] is not None:
                                stats += (
                                    newLine + beforeStaticLabel + '\tObjects with URIs (' +
                                    statsVersion['URIs'][0] + '): ' + resetColor +
                                    str(statsVersion['URIs'][1])
                                )
                            if COLORIZED_OUTPUT and not options.avoidColors:
                                beforeStaticLabel = warningColor
                            if statsVersion['Objects with JS code'] is not None:
                                stats += (
                                    newLine + beforeStaticLabel + '\tObjects with JS code (' +
                                    statsVersion['Objects with JS code'][0] + '): ' + resetColor +
                                    str(statsVersion['Objects with JS code'][1])
                                )
                            actions = statsVersion['Actions']
                            events = statsVersion['Events']
                            vulns = statsVersion['Vulns']
                            elements = statsVersion['Elements']
                            if events is not None or actions is not None or vulns is not None or elements is not None:
                                stats += newLine + beforeStaticLabel + '\tSuspicious elements:' + resetColor + newLine
                                if events is not None:
                                    for event in events:
                                        stats += (
                                            '\t\t' + beforeStaticLabel + event + ' (%d): ' % len(events[event]) +
                                            resetColor + str(events[event]) + newLine
                                        )
                                if actions is not None:
                                    for action in actions:
                                        stats += (
                                            '\t\t' + beforeStaticLabel + action + ' (%d): ' % len(actions[action]) +
                                            resetColor + str(actions[action]) + newLine
                                        )
                                if vulns is not None:
                                    for vuln in vulns:
                                        if vuln in vulnsDict:
                                            vulnName = vulnsDict[vuln][0]
                                            vulnCVEList = vulnsDict[vuln][1]
                                            stats += '\t\t' + beforeStaticLabel + vulnName + ' ('
                                            for vulnCVE in vulnCVEList:
                                                stats += vulnCVE + ','
                                            stats = stats[:-1] + ') (%d): ' % len(vulns[vuln]) + resetColor + str(vulns[vuln]) + newLine
                                        else:
                                            stats += (
                                                '\t\t' + beforeStaticLabel + vuln + ' (%d): ' % len(vulns[vuln]) +
                                                resetColor + str(vulns[vuln]) + newLine
                                            )
                                if elements is not None:
                                    for element in elements:
                                        if element in vulnsDict:
                                            vulnName = vulnsDict[element][0]
                                            vulnCVEList = vulnsDict[element][1]
                                            stats += '\t\t' + beforeStaticLabel + vulnName + ' ('
                                            for vulnCVE in vulnCVEList:
                                                stats += vulnCVE + ','
                                            stats = stats[:-1] + '): ' + resetColor + str(elements[element]) + newLine
                                        else:
                                            stats += '\t\t' + beforeStaticLabel + element + ': ' + resetColor + str(
                                                elements[element]) + newLine
                            if COLORIZED_OUTPUT and not options.avoidColors:
                                beforeStaticLabel = staticColor
                            urls = statsVersion['URLs']
                            if urls is not None:
                                stats += newLine + beforeStaticLabel + '\tFound URLs:' + resetColor + newLine
                                for url in urls:
                                    stats += '\t\t' + url + newLine
                            stats += newLine * 2
                    if fileName is not None:
                        print stats
                    if options.isInteractive:
                        from peepdf.PDFConsole import PDFConsole

                        console = PDFConsole(pdf, VT_KEY, options.avoidColors)
                        while not console.leaving:
                            try:
                                console.cmdloop()
                            except KeyboardInterrupt as e:
                                sys.exit()
                            except:
                                errorMessage = '*** Error: Exception not handled using the interactive console!! Please, report it to the author!!'
                                print errorColor + errorMessage + resetColor + newLine
                                traceback.print_exc(file=open(errorsFile, 'a'))
    except Exception as e:
        if len(e.args) == 2:
            excName, excReason = e.args
        else:
            excName = None
        if excName is None or excName != 'PeepException':
            errorMessage = '*** Error: Exception not handled!!'
            traceback.print_exc(file=open(errorsFile, 'a'))
        print errorColor + errorMessage + resetColor + newLine
    finally:
        if os.path.exists(errorsFile):
            message = newLine + 'Please, don\'t forget to report errors if found:' + newLine * 2
            message += '\t- Sending the file "%s" to the author (mailto:peepdfREMOVETHIS@eternal-todo.com)%s' % (
                errorsFile, newLine)
            message += '\t- And/Or creating an issue on the project webpage (https://github.com/jesparza/peepdf/issues)' + newLine
            message = errorColor + message + resetColor
            sys.exit(message)
