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
++++++++++++++++++++++++peepdf.py+++++++++++++++++++++++++
'''
author = 'Jose Miguel Esparza'
email = 'peepdf AT eternal-todo.com'
url = 'http://peepdf.eternal-todo.com'
twitter = 'http://twitter.com/EternalTodo'
peepTwitter = 'http://twitter.com/peepdf'
version = '0.3'
revision = '255'


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
MAX_OBJ_GAP = 4 + 2  # compensation for small offset bug
MAX_PRE_HEAD_GAP = 4
MAX_POST_EOF_GAP = 4
MAX_THRESHOLD_SCORE = 90
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
                       '/Flash',
                       '.rawValue',
                       'keep.previous']
monitorizedIndicators = {'versionBased':{
                             'invalidSubtype': ('Invalid stream /Subtype', 'stream'),
                             'invalidLength': ('Invalid stream /Length', 'stream'),
                             'largeSize': ('Large streams', 'stream'),
                             'nameObfuscated': ('Obfuscated names', '*'),
                             'stringObfuscated': ('Obfuscated strings', '*'),
                             'largeStringPresent': ('Large strings', '*'),
                             'missingXref': ('Missing in xref', '*'),
                             'streamTerminatorMissing': ('Missing stream terminator', 'stream'),
                             'terminatorMissing': ('Missing object terminator', '*'),
                             'garbageInside': ('Garbage bytes before terminator', '*'),
                             'duplicateObject': ('Duplicate Objects', '*'),
                             'missingCatalog': ('Not referenced from Catalog', '*')},
                         'fileBased':{
                             'brokenXref': 'Xref Table broken',
                             'illegalXref': 'Illegal entries in Xref',
                             'emptyXref': 'No entries in Xref Section',
                             'largeHeader': 'Header too large',
                             'largeBinaryHeader': 'Binary Header too large',
                             'garbageHeaderPresent': 'Garbage Header before PDF Header',
                             'badHeader': 'Bad PDF Header',
                             'missingEOF': '%%EOF missing',
                             'missingPages': '/Pages Missing',
                             'missingXref': 'Xref Missing',
                             'missingXrefEOL': 'Xref EOL Missing',
                             'missingCatalog': 'Catalog Missing',
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
errorsFile = 'errors.txt'
filter2RealFilterDict = {'b64':'base64','base64':'base64','asciihex':'/ASCIIHexDecode','ahx':'/ASCIIHexDecode','ascii85':'/ASCII85Decode','a85':'/ASCII85Decode','lzw':'/LZWDecode','flatedecode':'/FlateDecode','fl':'/FlateDecode','runlength':'/RunLengthDecode','rl':'/RunLengthDecode','ccittfax':'/CCITTFaxDecode','ccf':'/CCITTFaxDecode','jbig2':'/JBIG2Decode','dct':'/DCTDecode','jpx':'/JPXDecode'}



'''
++++++++++++++++++++++++JSAnalysis.py++++++++++++++++++++++++
'''
reJSscript = '<script[^>]*?contentType\s*?=\s*?[\'"]application/x-javascript[\'"][^>]*?>(.*?)</script>'
preDefinedCode = 'var app = this;'



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
    "Xref Table broken": 7,
    "No entries in Xref Section": 9,
    "Binary Header too large": 5,
    "Bad PDF Header": 4,
    "%%EOF missing": 5,
    "Xref Missing": 6,
    "Catalog Missing": 6,
    "Xref EOL Missing": 6,
    "missingInfo": 6,
    "/Pages Missing": 6,
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
    "/OpenAction": [6, 8],
    "/RichMedia": [5, 7],
    "/Flash": [5, 7],
    "/SubmitForm": [5, 7],
    "/XFA": [5, 7],
    "Garbage Bytes before": [6, 8],
    "Whitespace gap before": [4, 7],
    "Invalid stream /Length": [5, 7],
    "Invalid stream /Subtype": [4, 7],
    "Large streams": [5, 7],
    "Large strings": [5, 7],
    "Missing in xref": [7, 9],
    "Missing object terminator": [5, 8],
    "Missing stream terminator": [5, 8],
    "Not referenced from Catalog": [5, 7],
    "Obfuscated names": [4, 7],
    "Obfuscated strings": [3, 6],
    "getPageNthWord": [5, 7],
    "arguments.callee": [5, 7],
    "Xref Table missing": [6, 8],
    "containingJS": [5, 7],
    "Garbage bytes before terminator": [6, 8],
    "Duplicate Objects": [6,8],
    "Object Parsing Errors": [5,10],

    # Int/Tuple return
    "pagesNumber": "3 if x is not None and int(x)<=1 else 0",
    "detectionRate": "0 if x==None else (float(x[0])/float(x[1]))*20"

}


# PDF Builder List
UNKNOWN_BUILDER_SCORE = 7
MAX_BUILDER_SCORE = 9
PDFBuildersScore = {
    # Todo: add more creators
    "Acrobat Distiller": 0,
    "Acrobat PDFMaker": 0,
    "Acrobat PDFWriter": 0,
    "Adobe Acrobat": 0,
    "AdobePS5.dll": 0,
    "PDF Printer": 0,
    "Microsoft PowerPoint": 0,
    "Word": 0,
    "Mac OS X PDFContext": 0,
    "Ghostscript": 0,
    "FrameMaker": 0,
    "Hewlett-Packard Intelligent Scanning Technology": 0,
    "Arbortext Advanced Print Publisher": 0,
    "Total Publishing System": 0,
    "Copyright": 0,
    "Elsevier": 0,
    "Adobe InDesign": 0,
    "LaTeX": 0,
    "Adobe PageMaker": 0,
    "Adobe PDF Library": 0,
    "iText": 0,
    "Bullzip PDF Printer": 0,
    "CC PDF Converter": 0,
    "CutePDF": 0,
    "deskPDF": 0,
    "doPDF": 0,
    "eCopy PaperWorks": 0,
    "Foxit PhantomPDF": 0,
    "gDoc Creator": 0,
    "HelpNDoc": 0,
    "Nitro PDF Reader": 0,
    "NovaPDF": 0,
    "PagePlus": 0,
    "PaperPort": 0,
    "PDFCreator": 0,
    "PDF-XChange": 0,
    "PrimoPDF": 0,
    "SaveasPDFandXPS": 0,
    "Solid PDF Creator": 0,
    "Universal Document Converter": 0,
    "Xara Photo & Graphic Designer": 0,
    "Adobe Photoshop": 0,
    "LibreOffice": 0,
    "Nitro PDF Pro": 0,
    "pdftk": 0,
    "PDF-XChange Viewer": 0,
    "Solid PDF Tools": 0,
    "Microsoft Word": 0,
    "PDFescape": 0,
    "PDFVue": 0,
    "gDoc Fusion": 0,
    "OmniPage": 0,
    "Qiqqa": 0,
    "PDF Studio": 0,
    "PDF Signer": 0,
    "PDFSaM": 0,
    "deskUNPDF": 0,
    "Xpdf": 0,
    "Xournal": 0,
    "Antiword": 0,
    "dvipdfm": 0,
    "PScript5.dll": 0,
    "APJavaScript": 0,
    "OneForm Designer": 0,
    "purepdf": 0,
    "Scribus": 0,
    "OpenOffice": 0,
    "Writer": 0,

}
