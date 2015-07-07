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
    This module contains constants and globals used throughout peepdf
'''

import os


'''
++++++++++++++++++++++++PDFCore.py++++++++++++++++++++++++
'''
VT_KEY = 'fc90df3f5ac749a94a94cb8bf87e05a681a2eb001aef34b6a0084b8c22c97a64'
MAL_ALL = 1
MAL_HEAD = 2
MAL_EOBJ = 3
MAL_ESTREAM = 4
MAL_XREF = 5
MAL_BAD_HEAD = 6
MAX_HEAD_VER_LEN = 10
MAX_HEAD_BIN_LEN = 10
MAX_STR_LEN = 2000
MAX_STREAM_SIZE = 50000
MIN_STREAM_SIZE = 20
MAX_OBJ_GAP = 4 + 4  # compensation for ignored whitespaces
MAX_PRE_HEAD_GAP = 4
MAX_POST_EOF_GAP = 4
MAX_THRESHOLD_SCORE = 100
pdfFile = None
newLine = os.linesep
isForceMode = False
isManualAnalysis = False
spacesChars = ['\x00','\x09','\x0a','\x0c','\x0d','\x20']
delimiterChars = ['<<','(','<','[','{','/','%']
monitorizedEvents = ['/OpenAction ','/AA ','/Names ','/AcroForm ', '/XFA ']
monitorizedActions = ['/JS ','/JavaScript','/Launch','/SubmitForm','/ImportData']
monitorizedElements = ['/EmbeddedFiles ',
                       '/EmbeddedFile',
                       '/JBIG2Decode',
                       'getPageNthWord',
                       'arguments.callee',
                       '/U3D',
                       '/PRC',
                       '/RichMedia',
                       '.rawValue',
                       'keep.previous']
monitorizedIndicators = {'versionBased':{
                             'invalidSubtype': ('Invalid stream /Subtype', 'stream'),
                             'invalidLength': ('Invalid stream /Length', 'stream'),
                             'largeSize': ('Large streams', 'stream'),
                             'smallSize': ('Small streams', 'stream'),
                             'nameObfuscated': ('Obfuscated names', '*'),
                             'stringObfuscated': ('Obfuscated strings', '*'),
                             'largeStringPresent': ('Large strings', '*'),
                             'missingXref': ('Missing in xref', '*'),
                             'streamTerminatorMissing': ('Missing stream terminator', 'stream'),
                             'terminatorMissing': ('Missing object terminator', '*'),
                             'garbageInside': ('Garbage bytes before terminator', '*'),
                             'missingCatalog': ('Not referenced from Catalog', '*')},
                         'fileBased':{
                             'brokenXref': 'Xref Table broken',
                             'illegalXref': 'Illegal entries in Xref',
                             'largeHeader': 'Header too large',
                             'largeBinaryHeader': 'Binary Header too large',
                             'garbageHeaderPresent': 'Garbage Header before PDF Header',
                             'gapBeforeHeaderPresent': 'Large Gap before Header',
                             'garbageAfterEOFPresent': 'Garbage Bytes after last %EOF',
                             'gapAfterEOFPresent': 'Large gap after last %EOF'}}
jsVulns = ['mailto',
           'Collab.collectEmailInfo',
           'util.printf',
           'getAnnots',
           'getIcon',
           'spell.customDictionaryOpen',
           'media.newPlayer',
           'doc.printSeps',
           'app.removeToolButton']
singUniqueName = 'CoolType.SING.uniqueName'
bmpVuln = 'BMP/RLE heap corruption'
vulnsDict = {'mailto':('mailto',['CVE-2007-5020']),
             'Collab.collectEmailInfo':('Collab.collectEmailInfo',['CVE-2007-5659']),
             'util.printf':('util.printf',['CVE-2008-2992']),
             '/JBIG2Decode':('Adobe JBIG2Decode Heap Corruption',['CVE-2009-0658']),
             'getIcon':('getIcon',['CVE-2009-0927']),
             'getAnnots':('getAnnots',['CVE-2009-1492']),
             'spell.customDictionaryOpen':('spell.customDictionaryOpen',['CVE-2009-1493']),
             'media.newPlayer':('media.newPlayer',['CVE-2009-4324']),
             '.rawValue':('Adobe Acrobat Bundled LibTIFF Integer Overflow',['CVE-2010-0188']),
             singUniqueName:(singUniqueName,['CVE-2010-2883']),
             'doc.printSeps':('doc.printSeps',['CVE-2010-4091']),
             '/U3D':('/U3D',['CVE-2009-3953','CVE-2009-3959','CVE-2011-2462']),
             '/PRC':('/PRC',['CVE-2011-4369']),
             'keep.previous':('Adobe Reader XFA oneOfChild Un-initialized memory vulnerability',['CVE-2013-0640']), # https://labs.portcullis.co.uk/blog/cve-2013-0640-adobe-reader-xfa-oneofchild-un-initialized-memory-vulnerability-part-1/
             bmpVuln:(bmpVuln,['CVE-2013-2729']),
             'app.removeToolButton':('app.removeToolButton',['CVE-2013-3346'])}
jsContexts = {'global':None}



'''
++++++++++++++++++++++++PDFConsole.py++++++++++++++++++++++++
'''
# File and variable redirections
FILE_WRITE = 1
FILE_ADD = 2
VAR_WRITE = 3
VAR_ADD = 4
newLine = os.linesep
errorsFile = 'errors.txt'
filter2RealFilterDict = {'b64':'base64','base64':'base64','asciihex':'/ASCIIHexDecode','ahx':'/ASCIIHexDecode','ascii85':'/ASCII85Decode','a85':'/ASCII85Decode','lzw':'/LZWDecode','flatedecode':'/FlateDecode','fl':'/FlateDecode','runlength':'/RunLengthDecode','rl':'/RunLengthDecode','ccittfax':'/CCITTFaxDecode','ccf':'/CCITTFaxDecode','jbig2':'/JBIG2Decode','dct':'/DCTDecode','jpx':'/JPXDecode'}



'''
++++++++++++++++++++++++Individual Indicator Scores (x/10)++++++++++++++++++++++++
'''

indicatorScores = {

    # Vulnerabilities
    ".rawValue": 10,
    "/JBIG2Decode": 10,
    "keep.previous": 10,
    "BMP/RLE heap corruption": 10,
    "Collab.collectEmailInfo": 10,
    "CoolType.SING.uniqueName": 10,
    "spell.customDictionaryOpen": 10,
    "keep.previous": 10,
    "mailto": 10,
    "app.removeToolButton": 10,
    "doc.printSeps": 10,
    "getAnnots": 10,
    "getIcon": 10,
    "media.newPlayer": 10,
    "util.printf": 10,
    "/U3D": 10,
    "/PRC": 10,

    # Boolean return
    "Garbage bytes between objects": 3,
    "Header too large": 5,
    "Illegal entries in Xref": 6,
    "Large Gap before Header": 5,
    "Large gap after last %EOF": 5,
    "Garbage Header before PDF Header": 8,
    "Garbage Bytes after last %EOF": 7,
    "Xref Table broken": 5,         # increase after offsets error fix
    "Binary Header too large": 5,
    "badHeader": 3,
    "missingEOF": 3,
    "missingXref": 3,
    "missingCatalog": 3,
    "missingInfo": 3,
    "missingPages": 3,
    "File encrypted with default password": 5,

    # List return
    # (min_score, max_score)
    # max_score checked against min_score+len(x)
    "/AA": [5, 7],
    "/AcroForm": [5, 7],
    "/EmbeddedFile": [5, 7],
    "/EmbeddedFiles": [5, 7],
    "/ImportData": [5, 7],
    "/JS": [5, 7],
    "/JavaScript": [5, 7],
    "/Launch": [5, 7],
    "/Names": [3, 5],
    "/OpenAction": [5, 7],
    "/RichMedia": [5, 7],
    "/SubmitForm": [5, 7],
    "/XFA": [5, 7],
    "Garbage Bytes before": [3, 6],     # increase after offsets error fix
    "Whitespace gap before": [3, 6],     # increase after offsets error fix
    "Invalid stream /Length": [4, 7],
    "Invalid stream /Subtype": [4, 7],
    "Large streams": [5, 7],
    "Small streams": [5, 7],
    "Large strings": [5, 7],
    "Missing in xref": [5, 7],
    "Missing object terminator": [3, 6],
    "Missing stream terminator": [3, 6],
    "Not referenced from Catalog": [3, 6],
    "Obfuscated names": [4, 7],
    "Obfuscated strings": [3, 6],
    "getPageNthWord": [5, 7],
    "arguments.callee": [5, 7],
    "Xref Table missing": [6, 8],
    "containingJS": [5, 7],
    "Garbage bytes before terminator": [6, 8],

    # Int/Tuple return
    "pagesNumber": "3 if x==None or x<=2 else 2",
    "detectionRate": "0 if x==None else (float(x[0])/float(x[1]))*20"

}
