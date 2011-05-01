#
#    peepdf is a tool to analyse and modify PDF files
#    http://peepdf.eternal-todo.com
#    By Jose Miguel Esparza <jesparza AT eternal-todo.com>
#
#    Copyright (C) 2011 Jose Miguel Esparza
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
    PDFConsole.py
    Implementation of the interactive console of peepdf
'''

import cmd, sys, os, re, subprocess, optparse, hashlib
from PDFUtils import *
from PDFCrypto import *
from JSAnalysis import *
from PDFCore import *
from base64 import b64encode,b64decode
from PDFFilters import decodeStream,encodeStream
try:
    from spidermonkey import Runtime
    JS_MODULE = True
except ImportError, e:
    JS_MODULE = False
    
newLine = os.linesep
filter2RealFilterDict = {'b64':'base64','base64':'base64','asciihex':'/ASCIIHexDecode','ahx':'/ASCIIHexDecode','ascii85':'/ASCII85Decode','a85':'/ASCII85Decode','lzw':'/LZWDecode','flatedecode':'/FlateDecode','fl':'/FlateDecode','runlength':'/RunLengthDecode','rl':'/RunLengthDecode','ccittfax':'/CCITTFaxDecode','ccf':'/CCITTFaxDecode','jbig2':'/JBIG2Decode','dct':'/DCTDecode','jpx':'/JPXDecode'}

class PDFConsole(cmd.Cmd):
    
    def __init__(self, pdfFile, stdin = None):
        cmd.Cmd.__init__(self, stdin = stdin)
        self.prompt = 'PPDF> '
        self.use_rawinput = True
        if stdin != None:
            self.use_rawinput = False
            self.prompt = '' 
        self.pdfFile = pdfFile
        self.variables = {'output':['stdout','stdout'], # value and default value
                          'output_limit':[None,None],
                          'malformed_options':[[],[]],
                          'header_file':[None,None],
                          'sctest':[None,None]} 
        self.validVariableValues = {'output':['stdout','file','variable']}
        self.readOnlyVariables = ['malformed_options','header_file']
        self.loggingFile = None
        self.output = None
        
    def emptyline(self):
        return
        
    def precmd(self, line):
        if line == 'EOF':
            return 'exit'
        else:
            return line

    def do_bytes(self, argv):
        if self.pdfFile == None:
            message = '*** Error: You must open a file!!'
            self.log_output('bytes ' + argv, message)
            return False
        bytes = ''
        args = self.parseArgs(argv)
        if args == None:
            message = '*** Error: parsing arguments!!'
            self.log_output('bytes ' + argv, message)
            return False
        numArgs = len(args)
        if numArgs == 2 or numArgs == 3:
            offset = int(args[0])
            size = int(args[1])
            ret = getBytesFromFile(self.pdfFile.getPath(),offset,size)
            if ret[0] == -1:
                message = '*** Error: the file does not exist!!'
                self.log_output('bytes ' + argv, message)
                return False
            bytes = ret[1]
            if numArgs == 2:
                self.log_output('bytes ' + argv, bytes, storeOutput = True, bytesOutput = True)
            else:
                outputFile = args[2]
                open(outputFile,'w').write(bytes)
        else:
            self.help_bytes()
                
    def help_bytes(self):
        print newLine + 'Usage: bytes offset num_bytes [file]'
        print newLine + 'Show or store in the specified file "num_bytes" of the file beginning from "offset"' + newLine    

    def do_changelog(self, argv):
        if self.pdfFile == None:
            message = '*** Error: You must open a file!!'
            self.log_output('changelog ' + argv, message)
            return False
        output = ''
        args = self.parseArgs(argv)
        if args == None:
            message = '*** Error: parsing arguments!!'
            self.log_output('changelog ' + argv, message)
            return False
        if len(args) == 0:
            version = None
        elif len(args) == 1:
            version = args[0]
        else:
            self.help_changelog()
            return False
        if version != None and not version.isdigit():
            self.help_changelog()
            return False
        if version != None:
            version = int(version)
            if version > self.pdfFile.getNumUpdates():
                message = '*** Error: the version number is not valid'
                self.log_output('changelog ' + argv, message)
                return False
        if version == 0 or (version == None and self.pdfFile.getNumUpdates() == 0):
            message = '*** No changes!!'
            self.log_output('changelog ' + argv, message)
            return False
        # Getting information about original document
        data = self.pdfFile.getBasicMetadata(0)
        if data.has_key('author'):
            output += '\tAuthor: ' + data['author'] + newLine
        if data.has_key('creator'):
            output += '\tCreator: ' + data['creator'] + newLine
        if data.has_key('producer'):
            output += '\tProducer: ' + data['producer'] + newLine
        if data.has_key('creation'):
            output += '\tCreation date: ' + data['creation'] + newLine
        if output != '':
            output = 'Original document information:' + newLine + output + newLine
        
        # Getting changes for versions
        changes = self.pdfFile.getChangeLog(version)
        for i in range(len(changes)):
            changelog = changes[i]
            if changelog == [[],[],[],[]]:
                output += 'No changes in version ' + str(i+1) + newLine
            else:
                output += 'Changes in version ' + str(i+1) + ':' + newLine
            # Getting modification information
            data = self.pdfFile.getBasicMetadata(i+1)
            if data.has_key('author'):
                output += '\tAuthor: ' + data['author'] + newLine
            if data.has_key('creator'):
                output += '\tCreator: ' + data['creator'] + newLine
            if data.has_key('producer'):
                output += '\tProducer: ' + data['producer'] + newLine
            if data.has_key('modification'):
                output += '\tModification date: ' + data['modification'] + newLine
            addedObjects = changelog[0]
            modifiedObjects = changelog[1]
            removedObjects = changelog[2]
            notMatchingObjects = changelog[3]
            if addedObjects != []:
                output += '\tAdded objects: ' + str(addedObjects) + newLine
            if modifiedObjects != []:
                output += '\tModified objects: ' + str(modifiedObjects) + newLine
            if removedObjects != []:
                output += '\tRemoved objects: ' + str(removedObjects) + newLine
            if notMatchingObjects != []:
                output += '\tIncoherent objects: ' + str(notMatchingObjects) + newLine
            output += newLine
        self.log_output('changelog ' + argv, output, storeOutput = True)
        
    def help_changelog(self):
        print newLine + 'Usage: changelog [version]'
        print newLine + 'Show the changelog of the document or version of the document' + newLine

    def do_create(self, argv):
        message = ''
        validCreateTypes = ['pdf','object_stream']
        args = self.parseArgs(argv)
        if args == None:
            message = '*** Error: parsing arguments!!'
            self.log_output('create ' + argv, message)
            return False
        numArgs = len(args)
        if numArgs == 0:
            self.help_create()
            return False
        elementType = args[0]
        if elementType not in validCreateTypes:
            self.help_create()
            return False
        if elementType == 'pdf':
            content = ''
            validPDFTypes = ['simple','open_action_js']
            pdfType = 'simple'
            if numArgs > 1:
                pdfType = args[1]
                if pdfType not in validPDFTypes:
                    self.help_create()
                    return False
                if pdfType == 'open_action_js':
                    if numArgs > 3:
                        self.help_create()
                        return False
                    elif numArgs == 3:
                        jsFile = args[2]
                        if not os.path.exists(jsFile):
                            message = '*** Error: the file "'+jsFile+'" does not exist!!'
                            self.log_output('create ' + argv, message)
                            return False
                        content = open(jsFile,'r').read()
                    else:
                        if self.use_rawinput:
                            content = raw_input(newLine+'Please, specify the Javascript code you want to include in the file (if the code includes EOL characters use a js_file instead):' + newLine*2)
                        else:
                            message = '*** Error: in batch mode you must specify a Javascript file!!'
                            self.log_output('create ' + argv, message)
                            return False
                elif pdfType == 'simple':
                    if numArgs > 2:
                        self.help_create()
                        return False
            self.pdfFile = PDFFile()
            ret = self.pdfFile.makePDF(pdfType,content)
            if ret[0] == 0:
                message = 'PDF structure created successfully!!'
            else:
                message = '*** Error: an error occurred while creating the PDF structure!!'
            self.log_output('create ' + argv, message)
        elif elementType == 'object_stream':
            if self.pdfFile == None:
                message = '*** Error: You must open a file!!'
                self.log_output('create ' + argv, message)
                return False
            objectsToCompress = []
            streamContent = None
            version = None
            if numArgs == 2:
                version = args[1]
            elif numArgs > 2:
                self.help_create()
                return False
            if version != None and not version.isdigit():
                self.help_create()
                return False
            if version != None:
                version = int(version)
                if version > self.pdfFile.getNumUpdates():
                    message = '*** Error: the version number is not valid'
                    self.log_output('create ' + argv, message)
                    return False
            warning = 'Warning: stream objects cannot be compressed. If the Catalog object is compressed could lead to corrupted files for Adobe Reader!!'
            if self.use_rawinput:
                res = raw_input(warning+newLine+'Which objects do you want to compress? (Valid respones: all | 1-5 | 1,2,5,7,8) ')
            else:
                res = 'all'
            if res == 'all':
                objects = []
            elif res.count('-') == 1:
                limits = res.split('-')
                objects = range(int(limits[0]),int(limits[1])+1)
            elif res.find(',') != -1:
                objects = [int(id) for id in res.split(',')]
            elif res.isdigit():
                objects = [int(res)]
            else:
                message = '*** Error: the response format is not valid. It should be: all | 1-13 | 1,3,5,8'
                self.log_output('create ' + argv, message)
                return False
            ret = self.pdfFile.createObjectStream(version, objectIds = objects)
            if ret[0] == -1:
                error = ret[1]
                if error.find('Error') != -1:
                    message = '*** Error: '+ret[1]+'!!'
                    self.log_output('create ' + argv, message)
                    return False
                else:
                    message = '*** Warning: '+ret[1]+'!!'
            id = ret[1]
            if id == None:
                message = '*** Error: the object stream has NOT been created!!'
                self.log_output('create ' + argv, message)
                return False
            else:
                if message != '':
                    message += newLine*2
                message += 'The object stream has been created successfully'
            self.log_output('create ' + argv, message)        
                            
    def help_create(self):
        print newLine + 'Usage: create pdf simple|(open_action_js [js_file])'
        print newLine + 'Create a new simple PDF file or one with Javascript code to be executed when opening the file. It\'s possible to specify the file where the Javascript code is stored or do it manually.' + newLine*2
        print 'Usage: create object_stream [version]' + newLine
        print 'Create an object stream choosing the objects to be compressed.' + newLine
        
    def do_decode(self, argv):
        decodedContent = ''
        src = ''
        offset = 0
        size = 0
        validTypes = ['variable','file','raw']
        notImplementedFilters = ['ccittfax''ccf','jbig2','dct','jpx']
        filters = []
        args = self.parseArgs(argv)
        if args == None:
            message = '*** Error: parsing arguments!!'
            self.log_output('decode ' + argv, message)
            return False
        if len(args) > 2:
            type = args[0]
            iniFilterArgs = 2
            if type not in validTypes:
                self.help_decode()
                return False
            if type == 'variable' or type == 'file':
                src = args[1]
            else:
                if self.pdfFile == None:
                    message = '*** Error: You must open a file!!'
                    self.log_output('decode ' + argv, message)
                    return False
                if len(args) < 3:
                    self.help_decode()
                    return False
                iniFilterArgs = 3
                offset = args[1]
                size = args[2]
                if not offset.isdigit() or not size.isdigit():
                    message = '*** Error: "offset" and "num_bytes" must be integers!!'
                    self.log_output('decode ' + argv, message)
                    return False
                offset = int(args[1])
                size = int(args[1])
            for i in range(iniFilterArgs,len(args)):
                filter = args[i].lower()
                if filter not in filter2RealFilterDict.keys():
                    self.help_decode()
                    return False
                if filter in notImplementedFilters:
                    message = '*** Error: filter "'+filter+'" not implemented yet!!'
                    self.log_output('decode ' + argv, message)
                    return False
                filters.append(filter)
        else:
            self.help_decode()
            return False
        
        if type == 'variable':
            if not self.variables.has_key(src):
                message = '*** Error: the variable does not exist!!'
                self.log_output('decode ' + argv, message)
                return False
            else:
                decodedContent = self.variables[src][0]
        elif type == 'file':
            if not os.path.exists(src):
                message = '*** Error: the file does not exist!!'
                self.log_output('decode ' + argv, message)
                return False
            else:
                decodedContent = open(src,'r').read()                
        else:
            ret = getBytesFromFile(self.pdfFile.getPath(),offset,size)
            if ret[0] == -1:
                message = '*** Error: the file does not exist!!'
                self.log_output('decode ' + argv, message)
                return False
            decodedContent = ret[1]
        if decodedContent == '':
            message = '*** Error: empty content!!'
            self.log_output('decode ' + argv, message)
            return False
        for filter in filters:
            realFilter = filter2RealFilterDict[filter]
            if realFilter == 'base64':
                try:
                    decodedContent = b64decode(decodedContent)
                except:
                    message = '*** Error: '+str(sys.exc_info()[1])+'!!'
                    self.log_output('decode ' + argv, message)
                    return False
            else:
                ret = decodeStream(decodedContent, realFilter)
                if ret[0] == -1:
                    message = '*** Error: '+ret[1]+'!!'
                    self.log_output('decode ' + argv, message)
                    return False
                decodedContent = ret[1]
        self.log_output('decode ' + argv, decodedContent, storeOutput = True, bytesOutput = True)
                                
    def help_decode(self):
        print newLine + 'Usage: decode variable var_name filter1 [filter2 ...]'
        print 'Usage: decode file file_name filter1 [filter2 ...]'
        print 'Usage: decode raw offset num_bytes filter1 [filter2 ...]' + newLine
        print 'Decode the content of the specified variable, file or object using the following filters or algorithms:'
        print '\tbase64,b64: Base64'
        print '\tasciihex,ahx: /ASCIIHexDecode'
        print '\tascii85,a85: /ASCII85Decode'
        print '\tlzw: /LZWDecode'
        print '\tflatedecode,fl: /FlateDecode'
        print '\trunlength,rl: /RunLengthDecode'
        print '\tccittfax,ccf: /CCITTFaxDecode (Not implemented)'
        print '\tjbig2: /JBIG2Decode (Not implemented)'
        print '\tdct: /DCTDecode (Not implemented)'
        print '\tjpx: /JPXDecode (Not implemented)' + newLine

    def do_embed(self, argv):
        fileType = 'application#2Fpdf'
        option = None
        version = None
        fileContent = None
        execute = False
        if self.pdfFile == None:
            message = '*** Error: You must open a file!!'
            self.log_output('embed ' + argv, message)
            return False
        args = self.parseArgs(argv)
        if args == None:
            message = '*** Error: parsing arguments!!'
            self.log_output('embed ' + argv, message)
            return False
        numArgs = len(args)
        if numArgs == 1:
            fileName = args[0]
        elif numArgs == 2:
            if args[0] == '-x':
                fileName = args[1]
                execute = True
            else:
                fileName = args[0]
                fileType = args[1]
                if not os.path.exists(fileName):
                    self.help_embed()
                    return False
        elif numArgs == 3:
            option = args[0]
            fileName = args[1]
            fileType = args[2]
            if option != '-x':
                message = '*** Error: option not valid!!'
                self.log_output('embed ' + argv, message)
                return False
            execute = True    
        else:
            self.help_embed()
            return False
        
        if not os.path.exists(fileName):
            message = '*** Error: the file does not exist!!'
            self.log_output('embed ' + argv, message)
            return False
        fileContent = open(fileName,'rb').read()
        fileType = fileType.replace('/','#2F')
        
        # Check existent /Names in Catalog
        namesDict = None
        namesDictId = None
        namesToFilesDict = None
        namesToFilesDictId = None
        catalogObject = None
        catalogObjectId = None
        catalogIndirectObjects = self.pdfFile.getCatalogObject(indirect = True)
        for i in range(len(catalogIndirectObjects)-1,-1,-1):
            catalogIndirectObject = catalogIndirectObjects[i]
            if catalogIndirectObject != None:
                catalogObject = catalogIndirectObject.getObject()
                if catalogObject != None:
                    catalogObjectId = catalogIndirectObject.getId()
                    catalogObject = catalogIndirectObject.getObject()
                    version = i
                    if catalogObject.hasElement('/Names'):
                        namesDict = catalogObject.getElement('/Names')
                        namesDictType = namesDict.getType()
                        if namesDictType == 'reference':
                            namesDictId = namesDict.getId()
                            namesDict = self.pdfFile.getObject(namesDictId,version)
                        elif namesObjectType != 'dictionary':
                            message = '*** Error: bad type for /Names in Catalog!!'
                            self.log_output('embed ' + argv, message)
                            return False
                        if namesDict != None and namesDict.hasElement('/EmbeddedFiles'):
                            namesToFilesDict = namesDict.getElement('/EmbeddedFiles')
                            namesToFilesDictType = namesToFilesDict.getType()
                            if namesToFilesDictType == 'reference':
                                namesToFilesDictId = namesToFilesDict.getId()
                                namesToFilesDict = self.pdfFile.getObject(namesToFilesDictId,version)
                            elif namesToFilesDictType != 'dictionary':
                                message = '*** Error: bad type for /EmbeddedFiles element!!'
                                self.log_output('embed ' + argv, message)
                                return False
                    break
        if version == None:
            message = '*** Error: missing Catalog object!!'
            self.log_output('embed ' + argv, message)
            return False
        
        hexFileNameObject = PDFHexString(fileName.encode('hex'))
        md5Hash = hashlib.md5(fileContent).hexdigest()
        fileSize = len(fileContent)
        paramsDic = PDFDictionary(elements = {'/Size':PDFNum(str(fileSize)),'/Checksum':PDFHexString(md5Hash)})
        embeddedFileElements = {'/Type':PDFName('EmbeddedFile'),'/Subtype':PDFName(fileType),'/Params':paramsDic,'/Length':PDFNum(str(fileSize))}
        embeddedFileStream = PDFStream(rawStream = fileContent,elements = embeddedFileElements)
        embeddedFileStream.setElement('/Filter',PDFName('FlateDecode'))
        ret = self.pdfFile.setObject(None,embeddedFileStream,version)
        if ret[0] == -1:
            message = '*** Error: the embedded stream has not been created!!'
            self.log_output('embed ' + argv, message)
            return False
        embeddedFileStreamId = ret[1][0]
        embeddedListDict = PDFDictionary(elements = {'/F':PDFReference(str(embeddedFileStreamId))})
        fileSpecDict = PDFDictionary(elements = {'/Type':PDFName('Filespec'),'/F':PDFString(fileName),'/EF':embeddedListDict})
        ret = self.pdfFile.setObject(None,fileSpecDict,version)
        if ret[0] == -1:
            message = '*** Error: the Filespec dictionary has not been created!!'
            self.log_output('embed ' + argv, message)
            return False
        fileSpecDictId = ret[1][0]
        
        if namesToFilesDict != None:
            if namesToFilesDict.hasElement('/Names'):
                namesToFileArray = namesToFilesDict.getElement('/Names')
                namesToFileArrayType = namesToFileArray.getType()
                if namesToFileArrayType == 'reference':
                    namesToFileArrayId = namesToFileArray.getId()
                    namesToFileArray = self.pdfFile.getObject(namesToFileArrayId,version)
                elif namesToFileArrayType != 'array':
                    message = '*** Error: bad type for /Names in /EmbeddedFiles element!!'
                    self.log_output('embed ' + argv, message)
                    return False
                namesToFileArray.addElement(hexFileNameObject)
                namesToFileArray.addElement(PDFReference(str(fileSpecDictId)))
                if namesToFileArrayType == 'reference':
                    self.pdfFile.setObject(namesToFileArrayId,namesToFileArray,version)
                else:
                    namesToFilesDict.setElement('/Names',namesToFileArray)
                    if namesToFilesDictId != None:
                        ret = self.pdfFile.setObject(namesToFilesDictId,namesToFilesDict,version)
                        if ret[0] == -1:
                            message = '*** Error: the /EmbeddedFiles dictionary has not been modified!!'
                            self.log_output('embed ' + argv, message)
                            return False
            elif namesToFilesDict.hasElement('/Kids'):
                message = '*** Error: not supported children nodes in the /EmbeddedFiles element!!'
                self.log_output('embed ' + argv, message)
                return False
            else:
                namesToFilesDict.setElement('/Names',PDFArray(elements = [hexFileNameObject,PDFReference(str(fileSpecDictId))]))
        else:
            namesToFilesDict = PDFDictionary(elements = {'/Names':PDFArray(elements = [hexFileNameObject,PDFReference(str(fileSpecDictId))])})
            

        if namesDict != None:
            if namesToFilesDictId == None:
                namesDict.setElement('/EmbeddedFiles',namesToFilesDict)
                if namesDictId != None:
                    ret = self.pdfFile.setObject(namesDictId,namesDict,version)
                    if ret[0] == -1:
                        message = '*** Error: the /Names dictionary has not been modified!!'
                        self.log_output('embed ' + argv, message)
                        return False    
        else:
            namesDict = PDFDictionary(elements = {'/EmbeddedFiles':namesToFilesDict})
        if namesDictId == None:
            catalogObject.setElement('/Names',namesDict)
            ret = self.pdfFile.setObject(catalogObjectId,catalogObject,version)
            if ret[0] == -1:
                message = '*** Error: the Catalog has not been modified!!'
                self.log_output('embed ' + argv, message)
                return False
            
        # Checking that the /Contents element is present
        if catalogObject.hasElement('/Pages'):
            pagesObject = catalogObject.getElement('/Pages')
            if pagesObject.getType() == 'reference':
                pagesObjectId = pagesObject.getId()
                pagesObject = self.pdfFile.getObject(pagesObjectId,version)
                if pagesObject != None:
                    if pagesObject.hasElement('/Kids'):
                        kidsObject = pagesObject.getElement('/Kids')
                        if kidsObject != None:
                            kidsObjectType = kidsObject.getType()
                            if kidsObjectType == 'reference':
                                kidsObjectId = kidsObject.getId()
                                kidsObject = self.pdfFile.getObject(kidsObjectId,version)
                            elif kidsObjectType != 'array':
                                message = '*** Error: bad type for /Kids element!!'
                                self.log_output('embed ' + argv, message)
                                return False
                            pageObjects = kidsObject.getElements()
                            if len(pageObjects) > 0:
                                firstPageObjectId = None
                                firstPageObject = pageObjects[0]
                                if firstPageObject != None and firstPageObject.getType() == 'reference':
                                    firstPageObjectId = firstPageObject.getId()
                                    firstPageObject = self.pdfFile.getObject(firstPageObjectId,version)
                                else:
                                    message = '*** Error: bad type for /Page reference!!'
                                    self.log_output('embed ' + argv, message)
                                    return False
                                if firstPageObject.getType() == 'dictionary':
                                    if not firstPageObject.hasElement('/Contents'):
                                        contentsStream = PDFStream(rawStream = '',elements = {'/Length':PDFNum('0')})
                                        ret = self.pdfFile.setObject(None,contentsStream,version)
                                        if ret[0] == -1:
                                            message = '*** Error: the /Contents stream has not been created!!'
                                            self.log_output('embed ' + argv, message)
                                            return False
                                        contentsStreamId = ret[1][0]
                                        firstPageObject.setElement('/Contents',PDFReference(str(contentsStreamId)))
                                    # Adding GoToE action
                                    if option != None:
                                        targetDict = PDFDictionary(elements = {'/N': hexFileNameObject, '/R': PDFName('C')})
                                        actionGoToEDict = PDFDictionary(elements = {'/S':PDFName('GoToE'),'/NewWindow':PDFBool('false'),'/T':targetDict})
                                        ret = self.pdfFile.setObject(None,actionGoToEDict,version)
                                        if ret[0] == -1:
                                            message = '*** Error: the /GoToE element has not been created!!'
                                            self.log_output('embed ' + argv, message)
                                            return False
                                        actionGoToEDictId = ret[1][0]
                                        aaDict = PDFDictionary(elements = {'/O':PDFReference(str(actionGoToEDictId))})
                                        firstPageObject.setElement('/AA',aaDict)
                                        ret = self.pdfFile.setObject(firstPageObjectId,firstPageObject,version)
                                        if ret[0] == -1:
                                            message = '*** Error: the /Page element has not been modified!!'
                                            self.log_output('embed ' + argv, message)
                                            return False
                                else:
                                    message = '*** Error: bad type for /Page element!!'
                                    self.log_output('embed ' + argv, message)
                                    return False
                            else:
                                message = '*** Error: missing /Page element!!'
                                self.log_output('embed ' + argv, message)
                                return False
                        else:
                            message = '*** Error: /Kids element corrupted!!'
                            self.log_output('embed ' + argv, message)
                            return False
                    else:
                        message = '*** Error: missing /Kids element!!'
                        self.log_output('embed ' + argv, message)
                        return False
                else:
                    message = '*** Error: /Pages element corrupted!!'
                    self.log_output('embed ' + argv, message)
                    return False
            else:
                message = '*** Error: bad type for /Pages element!!'
                self.log_output('embed ' + argv, message)
                return False
        else:
            message = '*** Error: missing /Pages element!!'
            self.log_output('embed ' + argv, message)
            return False
            
        if option != None:
            pass
            
        message = 'File embedded succesfully!!'
        self.log_output('open ' + argv, message)

    def help_embed(self):
        print newLine + 'Usage: embed [-x] filename [file_type]'
        print newLine + 'Embed the specified file in the actual PDF file. The default type is "application/pdf".' + newLine
        print 'Options:'
        print '\t-x: The file is executed when the actual PDF file is opened' + newLine

    def do_encode(self, argv):
        encodedContent = ''
        src = ''
        offset = 0
        size = 0
        validTypes = ['variable','file','raw']
        notImplementedFilters = ['ascii85','a85','runlength','rl','jbig2','jpx','ccittfax','ccf','dct']
        filters = []
        args = self.parseArgs(argv)
        if args == None:
            message = '*** Error: parsing arguments!!'
            self.log_output('encode ' + argv, message)
            return False
        if len(args) > 2:
            type = args[0]
            iniFilterArgs = 2
            if type not in validTypes:
                self.help_encode()
                return False
            if type == 'variable' or type == 'file':
                src = args[1]
            else:
                if self.pdfFile == None:
                    message = '*** Error: You must open a file!!'
                    self.log_output('decode ' + argv, message)
                    return False
                if len(args) < 3:
                    self.help_encode()
                    return False
                iniFilterArgs = 3
                offset = args[1]
                size = args[2]
                if not offset.isdigit() or not size.isdigit():
                    message = '*** Error: "offset" and "num_bytes" must be integers!!'
                    self.log_output('encode ' + argv, message)
                    return False
                offset = int(args[1])
                size = int(args[1])
            for i in range(iniFilterArgs,len(args)):
                filter = args[i].lower()
                if filter not in filter2RealFilterDict.keys():
                    self.help_encode()
                    return False
                if filter in notImplementedFilters:
                    message = '*** Error: filter "'+filter+'" not implemented yet!!'
                    self.log_output('encode ' + argv, message)
                    return False
                filters.append(filter)
        else:
            self.help_encode()
            return False
        
        if type == 'variable':
            if not self.variables.has_key(src):
                message = '*** Error: the variable does not exist!!'
                self.log_output('encode ' + argv, message)
                return False
            else:
                encodedContent = self.variables[src][0]
        elif type == 'file':
            if not os.path.exists(src):
                message = '*** Error: the file does not exist!!'
                self.log_output('encode ' + argv, message)
                return False
            else:
                encodedContent = open(src,'r').read()                
        else:
            ret = getBytesFromFile(self.pdfFile.getPath(),offset,size)
            if ret[0] == -1:
                message = '*** Error: the file does not exist!!'
                self.log_output('encode ' + argv, message)
                return False
            encodedContent = ret[1]
        if encodedContent == '':
            message = '*** Error: empty content!!'
            self.log_output('encode ' + argv, message)
            return False
        for filter in filters:
            realFilter = filter2RealFilterDict[filter]
            if realFilter == 'base64':
                encodedContent = b64encode(encodedContent)
            else:
                ret = encodeStream(encodedContent, realFilter)
                if ret[0] == -1:
                    message = '*** Error: '+ret[1]+'!!'
                    self.log_output('encode ' + argv, message)
                    return False
                encodedContent = ret[1]
        self.log_output('encode ' + argv, encodedContent, storeOutput = True, bytesOutput = True)
                                
    def help_encode(self):
        print newLine + 'Usage: encode variable var_name filter1 [filter2 ...]'
        print 'Usage: encode file file_name filter1 [filter2 ...]'
        print 'Usage: encode raw offset num_bytes filter1 [filter2 ...]' + newLine
        print 'Encode the content of the specified variable, file or object using the following filters or algorithms:'
        print '\tbase64,b64: Base64'
        print '\tasciihex,ahx: /ASCIIHexDecode'
        print '\tascii85,a85: /ASCII85Decode (Not implemented)'
        print '\tlzw: /LZWDecode'
        print '\tflatedecode,fl: /FlateDecode'
        print '\trunlength,rl: /RunLengthDecode (Not implemented)'
        print '\tccittfax,ccf: /CCITTFaxDecode (Not implemented)'
        print '\tjbig2: /JBIG2Decode (Not implemented)'
        print '\tdct: /DCTDecode (Not implemented)'
        print '\tjpx: /JPXDecode (Not implemented)' + newLine

    def do_encode_strings(self, argv):
        if self.pdfFile == None:
            message = '*** Error: You must open a file!!'
            self.log_output('encode_strings ' + argv, message)
            return False
        args = self.parseArgs(argv)
        if args == None:
            message = '*** Error: parsing arguments!!'
            self.log_output('encode_strings ' + argv, message)
            return False
        if len(args) == 0:
            ret = self.pdfFile.encodeChars()
            if ret[0] == -1:
                message = '*** Error: '+ret[1]+'!!'
                self.log_output('encode_strings ' + argv, message)
                return False
            message = 'File encoded successfully'
        elif len(args) == 1 or len(args) == 2:
            if len(args) == 1:
                version = None
            else:
                version = args[1]
            id = args[0]
            if (not id.isdigit() and id != 'trailer') or (version != None and not version.isdigit()):
                self.help_encode_strings()
                return False
            if version != None:
                version = int(version)
                if version > self.pdfFile.getNumUpdates():
                    message = '*** Error: the version number is not valid'
                    self.log_output('encode_strings ' + argv, message)
                    return False
            if id == 'trailer':
                ret = self.pdfFile.getTrailer(version)
                if ret == None or ret[1] == [] or ret[1] == None or ret[1] == [None,None]:
                    message = '*** Error: trailer not found!!'
                    self.log_output('encode_strings ' + argv, message)
                    return False
                else:
                    trailerArray = ret[1]
                    version = ret[0]
                if trailerArray[0] != None:
                    trailerArray[0].encodeChars()
                    ret = self.pdfFile.setTrailer(trailerArray,version)
                    if ret[0] == -1:
                        message = '*** Error: there were some problems in the modification process!!'
                        self.log_output('encode_strings ' + argv, message)
                        return False
                    message = 'Trailer encoded successfully'
            else:
                id = int(id)
                object = self.pdfFile.getObject(id, version)
                if object == None:
                    message = '*** Error: object not found!!'
                    self.log_output('encode_strings ' + argv, message)
                    return False
                objectType = object.getType()
                if objectType not in ['string','name','array','dictionary','stream']:
                    message = '*** Error: this type of object cannot be encoded!!'
                    self.log_output('encode_strings ' + argv, message)
                    return False
                ret = object.encodeChars()
                if ret[0] == -1:
                    message = '*** Error: '+ret[1]+'!!'
                    self.log_output('encode_strings ' + argv, message)
                    return False
                ret = self.pdfFile.setObject(id, object, version, True)
                if ret[0] == -1:
                    message = '*** Error: there were some problems in the modification process!!'
                    self.log_output('encode_strings ' + argv, message)
                    return False
                message = 'Object encoded successfully'
        else:
            self.help_encode_strings()
            return False
        self.log_output('encode_strings ' + argv, message, storeOutput = True)
                    
    def help_encode_strings(self):
        print newLine + 'Usage: encode_strings [id|trailer [version]]'
        print newLine + 'Encode the strings and names included in the file, object or trailer' + newLine

    def do_encrypt(self, argv):
        if self.pdfFile == None:
            message = '*** Error: You must open a file!!'
            self.log_output('encrypt ' + argv, message)
            return False
        args = self.parseArgs(argv)
        if args == None:
            message = '*** Error: parsing arguments!!'
            self.log_output('encrypt ' + argv, message)
            return False
        numArgs = len(args)
        if numArgs == 0:
            password = ''
        elif numArgs == 1:
            password = args[0]
        else:
            self.help_encrypt()
            return False
        ret = self.pdfFile.encrypt(password)
        if ret[0] == -1:
            message = '*** Error: '+ret[1]+'!!'
        else:
            message = 'File encrypted successfully!!'
        self.log_output('encrypt ' + argv, message)                    
        
    def help_encrypt(self):
        print newLine + 'Usage: encrypt [password]'
        print newLine + 'Encrypt the file with the default or specified password' + newLine

    def do_errors(self, argv):
        if self.pdfFile == None:
            message = '*** Error: You must open a file!!'
            self.log_output('errors ' + argv, message)
            return False
        errors = ''
        errorsArray = []
        args = self.parseArgs(argv)
        if args == None:
            message = '*** Error: parsing arguments!!'
            self.log_output('errors ' + argv, message)
            return False
        if len(args) == 0:
            errorsArray = self.pdfFile.getErrors()
            messages,counters = countArrayElements(errorsArray)
            for i in range(len(messages)):
                errors += messages[i] + ' ('+ str(counters[i]) +') ' + newLine
            if errors == '':
                errors = 'No errors!!'
            self.log_output('errors ' + argv, errors)
            return False
        elif len(args) == 1:
            version = None
        elif len(args) == 2:
            version = args[1]
        else:
            self.help_errors()
            return False
        id = args[0]
        if (not id.isdigit() and id != 'trailer' and id != 'xref') or (version != None and not version.isdigit()):
            self.help_errors()
            return False
        if version != None:
            version = int(version)
            if version > self.pdfFile.getNumUpdates():
                message = '*** Error: the version number is not valid'
                self.log_output('errors ' + argv, message)
                return False
        if id == 'xref':
            ret = self.pdfFile.getXrefSection(version)
            if ret == None or ret[1] == None or ret[1] == [] or ret[1] == [None,None]:
                message = '*** Error: xref section not found!!'
                self.log_output('errors ' + argv, message)
                return False
            else:
                xrefArray = ret[1]
            if xrefArray[0] != None:
                errorsArray = xrefArray[0].getErrors()
            if xrefArray[1] != None:    
                errorsArray += xrefArray[1].getErrors()
        elif id == 'trailer':
            ret = self.pdfFile.getTrailer(version)
            if ret == None or ret[1] == None or ret[1] == [] or ret[1] == [None,None]:
                message = '*** Error: trailer not found!!'
                self.log_output('errors ' + argv, message)
                return False
            else:
                trailerArray = ret[1]
            if trailerArray[0] != None:
                errorsArray = trailerArray[0].getErrors()
            if trailerArray[1] != None:    
                errorsArray += trailerArray[1].getErrors()
        else:
            id = int(id)
            object = self.pdfFile.getObject(id, version)
            if object == None:
                message = '*** Error: object not found!!'
                self.log_output('errors ' + argv, message)
                return False
            errorsArray = object.getErrors()
        messages,counters = countArrayElements(errorsArray)
        for i in range(len(messages)):
            errors += messages[i] + ' ('+ str(counters[i]) +') ' + newLine
        if errors == '':
            errors = 'No errors!!'
        self.log_output('errors ' + argv, errors)            
        
    def help_errors(self):
        print newLine + 'Usage: errors [object_id|xref|trailer [version]]'
        print newLine + 'Shows the errors of the file or object (object_id, xref, trailer)' + newLine
                
    def do_exit(self, argv):
        return True
    
    def help_exit(self):
        print newLine + 'Usage: exit'
        print newLine + 'Exits from the console' + newLine

    def do_filters(self, argv):
        if self.pdfFile == None:
            message = '*** Error: You must open a file!!'
            self.log_output('errors ' + argv, message)
            return False
        message = ''
        value = ''
        filtersArray = []
        notImplementedFilters = ['ascii85','a85','runlength','rl','jbig2','jpx','ccittfax','ccf','dct']
        iniFilterArgs = 1
        filters = []
        args = self.parseArgs(argv)
        if args == None:
            message = '*** Error: parsing arguments!!'
            self.log_output('filters ' + argv, message)
            return False
        if len(args) == 0:
            self.help_filters()
            return False
        elif len(args) == 1:
            version = None
        else:
            if args[1].isdigit():
                version = args[1]
                iniFilterArgs = 2
            else:
                version = None
            validFilters = filter2RealFilterDict.keys() + ['none']
            validFilters.remove('b64')
            validFilters.remove('base64')
            for i in range(iniFilterArgs,len(args)):
                filter = args[i].lower()
                if filter not in validFilters:
                    self.help_filters()
                    return False
                if filter in notImplementedFilters:
                    message = '*** Error: filter "'+filter+'" not implemented yet!!'
                    self.log_output('filters ' + argv, message)
                    return False
                filters.append(filter)
                
        id = args[0]
        if not id.isdigit() or (version != None and not version.isdigit()):
            self.help_filters()
            return False
        id = int(id)
        if version != None:
            version = int(version)
            if version > self.pdfFile.getNumUpdates():
                message = '*** Error: the version number is not valid'
                self.log_output('filters ' + argv, message)
                return False
            
        object = self.pdfFile.getObject(id, version)
        if object == None:
            message = '*** Error: object not found!!'
            self.log_output('filters ' + argv, message)
            return False
        if object.getType() != 'stream':
            message = '*** Error: The object doesn\'t contain any streams!!'
            self.log_output('filters ' + argv, message)
            return False
        errors = object.getErrors()
        if filters == []:
            if object.hasElement('/Filter'):
                value = object.getElementByName('/Filter').getValue()
            else:
                message = '*** Warning: No filters found in the object!!'
                self.log_output('filters ' + argv, message)
                return False
        else:
            value = object.getStream()
            if value == -1 or value == '':
                message = '*** Error: The stream cannot be decoded!!'
                self.log_output('filters ' + argv, message)
                return False
            if len(filters) == 1:
                if filters[0] == 'none':
                    object.delElement('/Filter')
                else:
                    filtersPDFName = PDFName(filter2RealFilterDict[filters[0]])
                    object.setElement('/Filter',filtersPDFName)
            else:
                while True:
                    if 'none' in filters:
                        filters.remove('none')
                    else:
                        break
                filters.reverse()
                for filter in filters:
                    filtersArray.append(PDFName(filter2RealFilterDict[filter]))
                if filtersArray != []: 
                    filtersPDFArray = PDFArray('',filtersArray)
                    object.setElement('/Filter',filtersPDFArray)
            ret = self.pdfFile.setObject(id, object, version)
            if ret[0] == -1:
                message = '*** Error: '+ret[1]+'!!'
                self.log_output('filters ' + argv, message)
                return False
            value = str(object.getRawValue())
            newErrors = object.getErrors()
            if newErrors != errors:
                message = 'Warning: Some errors found in the modification process!!' + newLine
        self.log_output('filters ' + argv, message+value, value, storeOutput = True)
            
    def help_filters(self):
        print newLine + 'Usage: filters object_id [version] [filter1 [filter2 ...]]'
        print newLine + 'Shows the filters found in the stream object or set the filters in the object (first filter is used first). The valid values for filters are the following:'
        print '\tnone: No filters'
        print '\tasciihex,ahx: /ASCIIHexDecode'
        print '\tascii85,a85: /ASCII85Decode (Not implemented)'
        print '\tlzw: /LZWDecode'
        print '\tflatedecode,fl: /FlateDecode'
        print '\trunlength,rl: /RunLengthDecode (Not implemented)'
        print '\tccittfax,ccf: /CCITTFaxDecode (Not implemented)'
        print '\tjbig2: /JBIG2Decode (Not implemented)'
        print '\tdct: /DCTDecode (Not implemented)'
        print '\tjpx: /JPXDecode (Not implemented)' + newLine
    
    def help_help(self):
        print newLine + 'Usage: help [command]'
        print newLine + 'Show the available commands or the usage of the specified command' + newLine
        
    def do_info(self, argv):
        if self.pdfFile == None:
            message = '*** Error: You must open a file!!'
            self.log_output('info ' + argv, message)
            return False
        stats = ''
        args = self.parseArgs(argv)
        if args == None:
            message = '*** Error: parsing arguments!!'
            self.log_output('info ' + argv, message)
            return False
        if len(args) == 0:
            statsDict = self.pdfFile.getStats()
            stats = 'File: ' + statsDict['File'] + newLine
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
                if statsVersion['Object Streams']:
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
                            stats += '\t\t' + element + ': ' + str(elements[element]) + newLine
                urls = statsVersion['URLs']
                if urls != None:
                    newLine + '\tFound URLs:' + newLine
                    for url in urls:
                        stats += '\t\t' + url + newLine
                stats += newLine * 2
            self.log_output('info ' + argv, stats, storeOutput = True)
            return False
        elif len(args) == 1:
            version = None
        elif len(args) == 2:
            version = args[1]
        else:
            self.help_info()
            return False
        id = args[0]
        if (not id.isdigit() and id != 'trailer' and id != 'xref') or (version != None and not version.isdigit()):
            self.help_info()
            return False
        if version != None:
            version = int(version)
            if version > self.pdfFile.getNumUpdates():
                message = '*** Error: the version number is not valid'
                self.log_output('info ' + argv, message)
                return False
        if id == 'xref':
            statsDict = {}
            ret = self.pdfFile.getXrefSection(version)
            if ret == None or ret[1] == None or ret[1] == [] or ret[1] == [None,None]:
                message = '*** Error: xref section not found!!'
                self.log_output('info ' + argv, message)
                return False
            else:
                xrefArray = ret[1]
            if xrefArray[0] != None:
                statsDict = xrefArray[0].getStats()
            if xrefArray[1] != None:    
                statsStream = xrefArray[1].getStats()
                for key in statsStream:
                    if not statsDict.has_key(key):
                        statsDict[key] = statsStream[key]
            if statsDict['Offset'] != None:
                stats += 'Offset: ' + statsDict['Offset'] + newLine
            stats += 'Size: ' + statsDict['Size'] + newLine
            if statsDict['Stream'] != None:
                stats += 'Stream: ' + statsDict['Stream'] + newLine
            else:
                stats += 'Stream: No' + newLine
            numSubSections = len(statsDict['Subsections'])
            stats += 'Subsections: ' + str(numSubSections) + newLine
            for i in range(numSubSections):
                subStats = statsDict['Subsections'][i]
                stats += '\tSubsection ' + str(i+1) + ':' + newLine
                stats += '\t\tEntries: ' + subStats['Entries'] + newLine
                if subStats['Errors'] != None:
                    stats += '\t\tErrors: ' + subStats['Errors'] + newLine
            if statsDict['Errors'] != None:
                stats += 'Errors: ' + statsDict['Errors'] + newLine
        elif id == 'trailer':
            statsDict = {}
            ret = self.pdfFile.getTrailer(version)
            if ret == None or ret[1] == None or ret[1] == [] or ret[1] == [None,None]:
                message = '*** Error: trailer not found!!'
                self.log_output('info ' + argv, message)
                return False
            else:
                trailerArray = ret[1]
            if trailerArray[0] != None:
                statsDict = trailerArray[0].getStats()
            if trailerArray[1] != None:    
                statsStream = trailerArray[1].getStats()
                for key in statsStream:
                    if not statsDict.has_key(key):
                        statsDict[key] = statsStream[key]
            if statsDict['Offset'] != None:
                stats += 'Offset: ' + statsDict['Offset'] + newLine
            stats += 'Size: ' + statsDict['Size'] + newLine
            if statsDict['Stream'] != None:
                stats += 'Stream: ' + statsDict['Stream'] + newLine
            else:
                stats += 'Stream: No' + newLine
            stats += 'Objects: ' + statsDict['Objects'] + newLine
            if statsDict['Root Object'] != None:
                stats += 'Root Object: ' + statsDict['Root Object'] + newLine
            else:
                stats += 'Root Object: No' + newLine
            if statsDict['Info Object'] != None:
                stats += 'Info Object: ' + statsDict['Info Object'] + newLine
            else:
                stats += 'Info Object: No' + newLine
            if statsDict['ID'] != None:
                stats += 'ID: ' + statsDict['ID'] + newLine
            if statsDict['Encrypted']:
                stats += 'Encrypted: Yes' + newLine
            else:
                stats += 'Encrypted: No' + newLine
            if statsDict['Errors'] != None:
                stats += 'Errors: ' + statsDict['Errors'] + newLine            
        else:
            id = int(id)
            indirectObject = self.pdfFile.getObject(id, version, indirect = True)
            if indirectObject == None:
                message = '*** Error: object not found!!'
                self.log_output('info ' + argv, message)
                return False
            statsDict = indirectObject.getStats()
            if statsDict['Offset'] != None:
                stats += 'Offset: ' + statsDict['Offset'] + newLine
            stats += 'Size: ' + statsDict['Size'] + newLine
            stats += 'Object: ' + statsDict['Object'] + newLine
            if statsDict['Object'] in ['dictionary','stream']:
                if statsDict['Type'] != None:
                    stats += 'Type: ' + statsDict['Type'] + newLine
                if statsDict['Subtype'] != None:
                    stats += 'Subtype: ' + statsDict['Subtype'] + newLine
                if statsDict['Object'] == 'stream':
                    stats += 'Length: ' + statsDict['Length'] + newLine
                    if statsDict['Real Length'] != None:
                        stats += 'Real length: ' + statsDict['Real Length'] + newLine
                    if statsDict['Encoded']:
                        stats += 'Encoded: Yes' + newLine
                        if statsDict['Stream File'] != None:
                            stats += 'Stream File: ' + statsDict['Stream File'] + newLine
                        stats += 'Filters: ' + statsDict['Filters'] + newLine
                        if statsDict['Filter Parameters']:
                            stats += 'Filter Parameters: Yes' + newLine
                        else:
                            stats += 'Filter Parameters: No' + newLine
                        if statsDict['Decoding Errors']:
                            stats += 'Decoding errors: Yes' + newLine
                        else:
                            stats += 'Decoding errors: No' + newLine
                    else:
                        stats += 'Encoded: No' + newLine
            if statsDict['Object'] != 'stream':
                if statsDict['Compressed in'] != None:
                    stats += 'Compressed in: ' + statsDict['Compressed in'] + newLine
            if statsDict['Object'] == 'dictionary':
                if statsDict['Action type'] != None:
                    stats += 'Action type: ' + statsDict['Action type'] + newLine
            stats += 'References: ' + statsDict['References'] + newLine
            if statsDict['JSCode']:
                stats += 'JSCode: Yes' + newLine
                if statsDict['Escaped Bytes']:
                    stats += 'Escaped bytes: Yes' + newLine
                if statsDict['URLs']:
                    stats += 'URLs: Yes' + newLine
            if statsDict['Errors']:
                if statsDict['Object'] == 'stream':
                    stats += 'Parsing Errors: ' + statsDict['Errors'] + newLine
                else:
                    stats += 'Errors: ' + statsDict['Errors'] + newLine
        self.log_output('info ' + argv, stats, storeOutput = True)        
        
    def help_info(self):
        print newLine + 'Usage: info [object_id|xref|trailer [version]]'
        print newLine + 'Shows information of the file or object (object_id, xref, trailer)' + newLine

    def do_js(self, argv):
        error = ''
        content = ''
        if not JS_MODULE:
            message = '*** Error: Spidermonkey is not installed!!'
            self.log_output('js ' + argv, message)
            return False
        validTypes = ['variable','file','object']
        args = self.parseArgs(argv)
        if args == None:
            message = '*** Error: parsing arguments!!'
            self.log_output('js ' + argv, message)
            return False
        if len(args) == 2:
            version = None
        elif len(args) == 3 and args[0] == 'object':
            version = args[2]
        else:
            self.help_js()
            return False
        type = args[0]
        src = args[1]
        if type not in validTypes:
            self.help_js()
            return False
        if type == 'variable':
            if not self.variables.has_key(src):
                message = '*** Error: the variable does not exist!!'
                self.log_output('js ' + argv, message)
                return False
            else:
                content = self.variables[src][0]
                if not isJavascript(content):
                    if self.use_rawinput:
                        res = raw_input('The variable may not contain Javascript code, do you want to continue? (y/n) ')
                        if res.lower() == 'n':
                            message = '*** Error: the variable does not contain Javascript code!!'
                            self.log_output('js ' + argv, message)
                            return False
                    else:
                        print 'Warning: the object may not contain Javascript code...' + newLine
        elif type == 'file':
            if not os.path.exists(src):
                message = '*** Error: the file does not exist!!'
                self.log_output('js ' + argv, message)
                return False
            else:
                content = open(src,'r').read()
                if not isJavascript(content):
                    if self.use_rawinput:
                        res = raw_input('The file may not contain Javascript code, do you want to continue? (y/n) ')
                        if res.lower() == 'n':
                            message = '*** Error: the file does not contain Javascript code!!'
                            self.log_output('js ' + argv, message)
                            return False            
                    else:
                        print 'Warning: the object may not contain Javascript code...' + newLine    
        else:
            if self.pdfFile == None:
                message = '*** Error: You must open a file!!'
                self.log_output('js ' + argv, message)
                return False
            if not src.isdigit() or (version != None and not version.isdigit()):
                self.help_js()
                return False
            src = int(src)
            if version != None:
                version = int(version)
                if version > self.pdfFile.getNumUpdates():
                    message = '*** Error: the version number is not valid'
                    self.log_output('js ' + argv, message)
                    return False
            object = self.pdfFile.getObject(src, version)
            if object != None:
                if object.containsJS():
                    content = object.getJSCode()[0]
                else:
                    if self.use_rawinput:
                        res = raw_input('The object may not contain Javascript code, do you want to continue? (y/n) ')
                        if res.lower() == 'n':
                            message = '*** Error: the object does not contain Javascript code!!'
                            self.log_output('js ' + argv, message)
                            return False
                    else:
                        print 'Warning: the object may not contain Javascript code...' + newLine
                    objectType = object.getType()
                    if objectType == 'stream':
                        content = object.getStream()
                    elif type == 'dictionary' or type == 'array':
                        element = object.getElementByName('/JS')
                        if element != None:
                            content = element.getValue()
                        else:
                            message = '*** Error: target not found!!'
                            self.log_output('js ' + argv, message)
                            return False
                    elif type == 'string' or type == 'hexstring':
                        content = object.getValue()
                    else:
                        message = '*** Error: target not found!!'
                        self.log_output('js ' + argv, message)
                        return False
            else:
                message = '*** Error: object not found!!'
                self.log_output('js ' + argv, message)
                return False
        
        oldStdErr = sys.stderr
        errorFile = open('jserror.log','w')
        sys.stderr = errorFile
        r = Runtime()
        context = r.new_context()
        #TODO: store spidermonkey results in a variable or file
        try:
            res=context.eval_script(content)
            self.log_output('js ' + argv, res)
        except:
            pass                
        errorFile.close()
        sys.stderr = oldStdErr
        errorFileContent = open('jserror.log','r').read()
        if errorFileContent != '' and errorFileContent.find('JavaScript error') != -1:
            lines = errorFileContent.split(newLine)
            for line in lines:
                if line.find('JavaScript error') != -1:
                    error += line + newLine
            self.log_output('js ' + argv, error) 
        
    def help_js(self):
        print newLine + 'Usage: js variable var_name'
        print 'Usage: js file file_name'
        print 'Usage: js object object_id [version]'
        print newLine + 'Executes the Javascript code stored in the specified variable, file or object' + newLine

    def do_js_analyse(self, argv):
        content = ''
        bytes = ''
        validTypes = ['variable','file','object']
        if not JS_MODULE:
            message = '*** Error: Spidermonkey is not installed!!'
            self.log_output('js_analyse ' + argv, message)
            return False
        args = self.parseArgs(argv)
        if args == None:
            message = '*** Error: parsing arguments!!'
            self.log_output('js_analyse ' + argv, message)
            return False
        if len(args) == 2:
            version = None
        elif len(args) == 3 and args[0] == 'object':
            version = args[2]
        else:
            self.help_js_analyse()
            return False
        type = args[0]
        src = args[1]
        if type not in validTypes:
            self.help_js_analyse()
            return False
        if type == 'variable':
            if not self.variables.has_key(src):
                message = '*** Error: the variable does not exist!!'
                self.log_output('js_analyse ' + argv, message)
                return False
            else:
                content = self.variables[src][0]
                if not isJavascript(content):
                    if self.use_rawinput:
                        res = raw_input('The variable may not contain Javascript code, do you want to continue? (y/n) ')
                        if res.lower() == 'n':
                            message = '*** Error: the variable does not contain Javascript code!!'
                            self.log_output('js_analyse ' + argv, message)
                            return False
                    else:
                        print 'Warning: the object may not contain Javascript code...' + newLine
        elif type == 'file':
            if not os.path.exists(src):
                message = '*** Error: the file does not exist!!'
                self.log_output('js_analyse ' + argv, message)
                return False
            else:
                content = open(src,'r').read()
                if not isJavascript(content):
                    if self.use_rawinput:
                        res = raw_input('The file may not contain Javascript code, do you want to continue? (y/n) ')
                        if res.lower() == 'n':
                            message = '*** Error: the file does not contain Javascript code!!'
                            self.log_output('js_analyse ' + argv, message)
                            return False                
                    else:
                        print 'Warning: the object may not contain Javascript code...' + newLine
        else:
            if self.pdfFile == None:
                message = '*** Error: You must open a file!!'
                self.log_output('js_analyse ' + argv, message)
                return False
            if not src.isdigit() or (version != None and not version.isdigit()):
                self.help_js_analyse()
                return False
            src = int(src)
            if version != None:
                version = int(version)
                if version > self.pdfFile.getNumUpdates():
                    message = '*** Error: the version number is not valid'
                    self.log_output('js_analyse ' + argv, message)
                    return False
            object = self.pdfFile.getObject(src, version)
            if object != None:
                if object.containsJS():
                    content = object.getJSCode()[0]
                else:
                    if self.use_rawinput:
                        res = raw_input('The object may not contain Javascript code, do you want to continue? (y/n) ')
                        if res.lower() == 'n':
                            message = '*** Error: the object does not contain Javascript code!!'
                            self.log_output('js_analyse ' + argv, message)
                            return False
                    else:
                        print 'Warning: the object may not contain Javascript code...' + newLine
                    objectType = object.getType()
                    if objectType == 'stream':
                        content = object.getStream()
                    elif type == 'dictionary' or type == 'array':
                        element = object.getElementByName('/JS')
                        if element != None:
                            content = element.getValue()
                        else:
                            message = '*** Error: target not found!!'
                            self.log_output('js_analyse ' + argv, message)
                            return False
                    elif type == 'string' or type == 'hexstring':
                        content = object.getValue()
                    else:
                        message = '*** Error: target not found!!'
                        self.log_output('js_analyse ' + argv, message)
                        return False
            else:
                message = '*** Error: object not found!!'
                self.log_output('js_analyse ' + argv, message)
                return False
            
        jsCode,unescapedBytes,urlsFound,jsErrors = analyseJS(content)
        if content not in jsCode:
            jsCode = [content] + jsCode
        jsanalyseOutput = ''
        if jsCode != []:
            jsanalyseOutput += newLine + 'Javascript code:' + newLine
            for js in jsCode:
                if js == jsCode[0]:
                    jsanalyseOutput += newLine + '==================== Original Javascript code ====================' + newLine*2
                else:
                    jsanalyseOutput += newLine + '================== Next stage of Javascript code ==================' + newLine*2
                jsanalyseOutput += js
                jsanalyseOutput += newLine*2 + '===================================================================' + newLine
        if unescapedBytes != []:
            jsanalyseOutput += newLine*2 + 'Unescaped bytes:' + newLine*2
            for bytes in unescapedBytes: 
                jsanalyseOutput += self.printBytes(bytes) + newLine*2
        if urlsFound != []:
            jsanalyseOutput += newLine*2 + 'URLs in shellcode:' + newLine*2
            for url in urlsFound:
                jsanalyseOutput += '\t' + url + newLine
        if jsErrors != []:
            jsanalyseOutput += newLine*2
            for jsError in jsErrors:
                jsanalyseOutput += 'Error analysing Javascript: ' + jsError + newLine
                
        self.log_output('js_analyse ' + argv, jsanalyseOutput, bytes, storeOutput =  True)        
        
    def help_js_analyse(self):
        print newLine + 'Usage: js_analyse variable var_name'
        print 'Usage: js_analyse file file_name'
        print 'Usage: js_analyse object object_id [version]'
        print newLine + 'Analyses the Javascript code stored in the specified variable, file or object' + newLine

    def do_js_code(self, argv):
        if self.pdfFile == None:
            message = '*** Error: You must open a file!!'
            self.log_output('js_code ' + argv, message)
            return False
        consoleOutput = ''
        args = self.parseArgs(argv)
        if args == None:
            message = '*** Error: parsing arguments!!'
            self.log_output('js_code ' + argv, message)
            return False
        if len(args) == 1:
            version = None
        elif len(args) == 2:
            version = args[1]
        else:
            self.help_js_code()
            return False
        id = args[0]
        if not id.isdigit() or (version != None and not version.isdigit()):
            self.help_js_code()
            return False
        id = int(id)
        if version != None:
            version = int(version)
            if version > self.pdfFile.getNumUpdates():
                message = '*** Error: the version number is not valid'
                self.log_output('js_code ' + argv, message)
                return False
        object = self.pdfFile.getObject(id, version)
        if object == None:
            message = '*** Error: object not found!!'
            self.log_output('js_code ' + argv, message)
            return False
        if object.containsJS():
            jsCode = object.getJSCode()
            if len(jsCode) > 1:
                if self.use_rawinput:
                    res = raw_input(newLine + 'There are more than one Javascript code, do you want to see all (1) or just the last one (2)? ')
                else:
                    res = '1'
                if res == '1':
                    for js in jsCode:
                        if js == jsCode[0]:
                            consoleOutput += newLine + '================== Original Javascript code ==================' + newLine
                        else:
                            consoleOutput += newLine + '================== Next stage of Javascript code ==================' + newLine
                        consoleOutput += js
                        consoleOutput += newLine + '===================================================================' + newLine
                else:
                    js = jsCode[-1]    
                    consoleOutput += newLine + js + newLine
            elif len(jsCode) == 1:
                consoleOutput += newLine + jsCode[0] + newLine
            self.log_output('js_code ' + argv, consoleOutput, storeOutput = True)
        else:
            message = '*** Error: Javascript code not found in this object!!'
            self.log_output('js_code ' + argv, message)
            
    def help_js_code(self):
        print newLine + 'Usage: js_code object_id [version]'
        print newLine + 'Shows the Javascript code found in the object' + newLine
        
    def do_js_join(self, argv):
        content = ''
        finalString = ''
        reSeparatedStrings = '["\'](.*?)["\']'
        validTypes = ['variable','file']
        args = self.parseArgs(argv)
        if args == None:
            message = '*** Error: parsing arguments!!'
            self.log_output('js_join ' + argv, message)
            return False
        if len(args) != 2:
            self.help_js_join()
            return False
        type = args[0]
        src = args[1]
        if type not in validTypes:
            self.help_js_join()
            return False
        if type == 'variable':
            if not self.variables.has_key(src):
                message = '*** Error: the variable does not exist!!'
                self.log_output('js_join ' + argv, message)
                return False
            else:
                content = self.variables[src][0]
        elif type == 'file':
            if not os.path.exists(src):
                message = '*** Error: the file does not exist!!'
                self.log_output('js_join ' + argv, message)
                return False
            else:
                content = open(src,'r').read()    
        strings = re.findall(reSeparatedStrings, content)
        if strings == []:
            message = '*** Error: the variable or file does not contain separated strings!!'
            self.log_output('js_join ' + argv, message)
            return False            
        for string in strings:
            finalString += string
        self.log_output('js_join ' + argv, finalString, storeOutput = True)
        
    def help_js_join(self):
        print newLine + 'Usage: js_join variable var_name'
        print 'Usage: js_join file file_name'
        print newLine + 'Joins some strings separated by quotes and stored in the specified variable or file in a unique one' + newLine
        print 'Example:' + newLine  
        print 'aux = "%u65"+"54"+"%u74"+"73"' + newLine
        print '> js_join variable aux' + newLine
        print '%u6554%u7473' + newLine

    def do_js_unescape(self, argv):
        content = ''
        unescapedOutput = ''
        bytes = ''
        reUnicodeChars = '(%u[0-9a-f]{4})+'
        reHexChars = '(%[0-9a-f]{2})+'
        validTypes = ['variable','file']
        args = self.parseArgs(argv)
        if args == None:
            message = '*** Error: parsing arguments!!'
            self.log_output('js_unescape ' + argv, message)
            return False
        if len(args) != 2:
            self.help_js_unescape()
            return False
        type = args[0]
        src = args[1]
        if type not in validTypes:
            self.help_js_unescape()
            return False
        if type == 'variable':
            if not self.variables.has_key(src):
                message = '*** Error: the variable does not exist!!'
                self.log_output('js_unescape ' + argv, message)
                return False
            else:
                content = self.variables[src][0]
                if not re.match(reUnicodeChars, content, re.IGNORECASE) and not re.match(reHexChars, content, re.IGNORECASE):
                    message = '*** Error: the variable does not contain escaped chars!!'
                    self.log_output('js_unescape ' + argv, message)
                    return False
        elif type == 'file':
            if not os.path.exists(src):
                message = '*** Error: the file does not exist!!'
                self.log_output('js_unescape ' + argv, message)
                return False
            else:
                content = open(src,'r').read()
                if not re.match(reUnicodeChars, content, re.IGNORECASE) and not re.match(reHexChars, content, re.IGNORECASE):
                    message = '*** Error: the file does not contain escaped chars!!'
                    self.log_output('js_unescape ' + argv, message)
                    return False                
        ret = unescape(content)
        if ret[0] != -1:
            unescapedBytes = ret[1]
            bytes = ret[1]
            urlsFound = re.findall('https?://.*$', unescapedBytes, re.DOTALL)
            if unescapedBytes != '':
                unescapedOutput += newLine + 'Unescaped bytes:' + newLine*2
                unescapedOutput += self.printBytes(unescapedBytes)
            if urlsFound != []:
                unescapedOutput += newLine*2 + 'URLs in shellcode:' + newLine
                for url in urlsFound:
                    unescapedOutput += '\t'+url
                unescapedOutput += newLine
        self.log_output('js_unescape ' + argv, unescapedOutput, bytes, storeOutput = True, bytesOutput = True)
        
    def help_js_unescape(self):
        print newLine + 'Usage: js_unescape variable var_name'
        print 'Usage: js_unescape file file_name'
        print newLine + 'Unescapes the escaped characters stored in the specified variable or file' + newLine
        print 'Example:' + newLine
        print 'aux = "%u6554%u7473"' + newLine
        print '> js_unescape variable aux' + newLine
        print '54 65 73 74                                       |Test|' + newLine

    def do_log(self, argv):
        args = self.parseArgs(argv)
        if args == None:
            message = '*** Error: parsing arguments!!'
            self.log_output('log ' + argv, message)
            return False
        numArgs = len(args)
        if numArgs == 0:
            if self.loggingFile == None:
                print newLine + 'Not logging now!!' + newLine
            else:
                print newLine + 'Log file: ' + self.loggingFile + newLine
        elif numArgs == 1:
            param = args[0]
            if param == 'stop':
                self.loggingFile = None
            else:
                self.loggingFile = param
        else:
            self.help_log()
            return False
        
    def help_log(self):
        print newLine + 'Usage: log'
        print newLine + 'Show the actual state of logging' + newLine
        print 'Usage: log stop'
        print newLine + 'Stop logging' + newLine
        print 'Usage: log log_file'
        print newLine + 'Starts logging in the specified file' + newLine

    def do_malformed_output(self, argv):
        malformedOptions = []
        headerFile = None
        args = self.parseArgs(argv)
        if args == None:
            message = '*** Error: parsing arguments!!'
            self.log_output('malformed_output ' + argv, message)
            return False
        if len(args) == 0:
            malformedOptions.append(1)
        else:
            for i in range(len(args)):
                opt = args[i]
                if opt.isdigit():
                    opt = int(opt)
                    if -1 < opt < 7:
                        if opt == 0:
                            malformedOptions = []
                            headerFile = None
                            break
                        else:
                            if opt not in malformedOptions and 1 not in malformedOptions:
                                malformedOptions.append(opt)
                    else:
                        self.help_malformed_output()
                        return False
                else:
                    if os.path.exists(opt):
                        headerFile = opt
                        break
                    else:
                        self.help_malformed_output()
                        return False
        self.variables['malformed_options'] = [malformedOptions, malformedOptions]
        self.variables['header_file'] = [headerFile, headerFile]
        message = 'Malformed options successfully enabled'
        self.log_output('malformed_output ' + argv, message, storeOutput = True)
        
    def help_malformed_output(self):
        print newLine + 'Usage: malformed_output [option1 [option2 ...] [header_file]]' + newLine
        print 'Enable malformed output when saving the file:' + newLine
        print '\t0: Removes all the malformed options.'
        print '\t1 [header_file]: Enable all the implemented tricks. Default option.'
        print '\t2 [header_file]: Puts the default or specified header before the PDF header.'
        print '\t3: Removes all the "endobj" tags.'
        print '\t4: Removes all the "endstream" tags.'
        print '\t5: Removes the "xref" section.'
        print '\t6: Bad header: %PDF-1' + newLine

    def do_metadata(self, argv):
        if self.pdfFile == None:
            message = '*** Error: You must open a file!!'
            self.log_output('metadata ' + argv, message)
            return False
        output = ''
        args = self.parseArgs(argv)
        if args == None:
            message = '*** Error: parsing arguments!!'
            self.log_output('metadata ' + argv, message)
            return False
        if len(args) == 0:
            version = None
        elif len(args) == 1:
            version = args[0]
        else:
            self.help_metadata()
            return False
        if version != None and not version.isdigit():
            self.help_metadata()
            return False
        if version != None:
            version = int(version)
            if version > self.pdfFile.getNumUpdates():
                message = '*** Error: the version number is not valid'
                self.log_output('metadata ' + argv, message)
                return False
        metadataObjects = self.pdfFile.getMetadata(version)
        if metadataObjects != []:
            if version != None:
                metadataObjects = [metadataObjects]
            for v in range(len(metadataObjects)):
                objects = metadataObjects[v]
                if version != None:
                    v = version
                infoObject = self.pdfFile.getInfoObject(v)
                if infoObject != None:
                    value = infoObject.getValue()
                    output += 'Info Object in version '+str(v)+':' + newLine*2+value+newLine*2
                if objects != []:
                    for id in objects:
                        object = self.pdfFile.getObject(id, v)
                        objectType = object.getType()
                        if objectType == 'dictionary' or objectType == 'stream':
                            type = object.getElementByName('/Type').getValue()
                            if type == '/Metadata':
                                value = object.getValue()
                                if value != '':
                                    output += 'Object '+str(id)+' in version '+str(v)+':' + newLine*2+value+newLine*2
            self.log_output('metadata ' + argv, output, storeOutput = True)
        else:
            message = '*** No metadata found!!'
            self.log_output('metadata ' + argv, message)
            return False
        
    def help_metadata(self):
        print newLine + 'Usage: metadata [version]'
        print newLine + 'Show the metadata of the document or version of the document' + newLine

    def do_modify(self, argv):
        maxDepth = 2
        validModifyTypes = ['object','stream']
        args = self.parseArgs(argv)
        if args == None:
            message = '*** Error: parsing arguments!!'
            self.log_output('modify ' + argv, message)
            return False
        numArgs = len(args)
        if numArgs < 2:
            self.help_modify()
            return False
        elementType = args[0]
        if elementType not in validModifyTypes:
            self.help_modify()
            return False
        else:
            # Checking arguments
            id = args[1]
            contentFile = None
            if numArgs == 2:
                version = None
            elif numArgs == 3:
                if not os.path.exists(args[2]):
                    version = args[2]
                else:
                    version = None
                    contentFile = args[2]
            elif numArgs == 4:
                version = args[2]
                contentFile = args[3]
                if not os.path.exists(contentFile):
                    message = '*** Error: the file "'+contentFile+'" does not exist!!'
                    self.log_output('modify ' + argv, message)
                    return False
            else:
                self.help_modify()
                return False
            if (not id.isdigit() and id != 'trailer' and id != 'xref') or (version != None and not version.isdigit()):
                self.help_modify()
                return False
            if version != None:
                version = int(version)
                if version > self.pdfFile.getNumUpdates():
                    message = '*** Error: the version number is not valid'
                    self.log_output('modify ' + argv, message)
                    return False
                
            id = int(id)
            object = self.pdfFile.getObject(id, version)
            if object == None:
                message = '*** Error: object not found!!'
                self.log_output('modify ' + argv, message)
                return False
            objectType = object.getType()
            if elementType == 'object':
                ret = self.modifyObject(object, 0, contentFile)
                if ret[0] == -1:
                    message = '*** Error: the object has not been modified!!'
                    self.log_output('modify ' + argv, message)
                    return False
                else:
                    object = ret[1]
            elif elementType == 'stream':
                if objectType != 'stream':
                    message = '*** Error: the specified object is not an stream object!!'
                    self.log_output('modify ' + argv, message)
                    return False
                if contentFile != None:
                    streamContent = open(contentFile,'r').read()
                else:
                    if self.use_rawinput:
                        streamContent = raw_input(newLine + 'Please, specify the stream content (if the content includes EOL characters use a file instead):' + newLine*2)
                    else:
                        message = '*** Error: in batch mode you must specify a file storing the stream content!!'
                        self.log_output('modify ' + argv, message)
                        return False
                object.setDecodedStream(streamContent)
            ret = self.pdfFile.setObject(id, object, version, mod=True)
            if ret[0] == -1:
                message = '*** Error: the object has not been modified!!'
            else:
                message = 'Object modified successfully!!'
            self.log_output('modify ' + argv, message)
                            
    def help_modify(self):
        print newLine + 'Usage: modify object|stream id [version] [file]' + newLine
        print 'Modify the object or stream specified. It\'s possible to use a file to retrieve the stream content (ONLY for stream content).' + newLine

    def do_object(self, argv):
        if self.pdfFile == None:
            message = '*** Error: You must open a file!!'
            self.log_output('object ' + argv, message)
            return False
        args = self.parseArgs(argv)
        if args == None:
            message = '*** Error: parsing arguments!!'
            self.log_output('object ' + argv, message)
            return False
        if len(args) == 1:
            version = None
        elif len(args) == 2:
            version = args[1]
        else:
            self.help_object()
            return False
        id = args[0]
        if not id.isdigit() or (version != None and not version.isdigit()):
            self.help_object()
            return False
        id = int(id)
        if version != None:
            version = int(version)
            if version > self.pdfFile.getNumUpdates():
                message = '*** Error: the version number is not valid'
                self.log_output('object ' + argv, message)
                return False
        object = self.pdfFile.getObject(id, version)
        if object == None:
            message = '*** Error: object not found!!'
            self.log_output('object ' + argv, message)
            return False
        value = object.getValue()
        self.log_output('object ' + argv, value, storeOutput = True)
        
    def help_object(self):
        print newLine + 'Usage: object object_id [version]'
        print newLine + 'Shows the content of the object after being decoded and decrypted.' + newLine

    def do_offsets(self, argv):
        if self.pdfFile == None:
            message = '*** Error: You must open a file!!'
            self.log_output('offsets ' + argv, message)
            return False
        version = None
        offsetsOutput = ''
        offsetsArray = []
        args = self.parseArgs(argv)
        if args == None:
            message = '*** Error: parsing arguments!!'
            self.log_output('offsets ' + argv, message)
            return False
        numArgs = len(args)
        if numArgs == 0:
            offsetsArray = self.pdfFile.getOffsets()
        elif numArgs == 1:
            version = args[0]
            if not version.isdigit():
                self.help_offsets()
                return False
            version = int(version)
            if version > self.pdfFile.getNumUpdates():
                message = '*** Error: the version number is not valid'
                self.log_output('offsets ' + argv, message)
                return False
            offsetsArray = self.pdfFile.getOffsets(version)
        else:
            self.help_offsets()
            return False
        
        for i in range(len(offsetsArray)):
            offsets = offsetsArray[i]
            if i == 0 and offsets.has_key('header'):
                offset,size = offsets['header']
                offsetsOutput += '%8d %s%s' % (offset,'Header',newLine)
            elif version == None:
                offsetsOutput += newLine + 'Version '+str(i)+':' + newLine*2
            if offsets.has_key('objects'):
                compressedObjects = offsets['compressed']
                sortedObjectList = sorted(offsets['objects'], key=lambda x: x[1])
                for id,offset,size in sortedObjectList:
                    #offsetsOutput += '%8d %s %d (%d)%s' % (offset,'Object ',id,size,newLine)
                    if id in compressedObjects:
                        offsetsOutput += '%8d%s%8s%s %d (%d)%s%8d%s' % (offset,newLine,'','Compressed Object ',id,size,newLine,offset+size-1,newLine)
                    else:
                        offsetsOutput += '%8d%s%8s%s %d (%d)%s%8d%s' % (offset,newLine,'','Object ',id,size,newLine,offset+size-1,newLine)
            if offsets['xref'] != None:
                offset, size = offsets['xref']
                #offsetsOutput += '%8d %s (%d)%s' % (offset,'Xref Section',size,newLine)
                offsetsOutput += '%8d%s%8s%s (%d)%s%8d%s' % (offset,newLine,'','Xref Section',size,newLine,offset+size-1,newLine)
            if offsets['trailer'] != None:
                offset, size = offsets['trailer']
                #offsetsOutput += '%8d %s (%d)%s' % (offset,'Trailer',size,newLine)
                offsetsOutput += '%8d%s%8s%s (%d)%s%8d%s' % (offset,newLine,'','Trailer',size,newLine,offset+size-1,newLine)
            if offsets['eof'] != None:
                offset, size = offsets['eof']
                offsetsOutput += '%8d %s%s' % (offset,'EOF',newLine)
                
        self.log_output('offsets ' + argv, offsetsOutput, storeOutput = True)
                    
    def help_offsets(self):
        print newLine + 'Usage: offsets [num_version]'
        print newLine + 'Shows the physical map of the file or the specified version of the document' + newLine

    def do_open(self, argv):
        forceMode = False
        looseMode = False
        
        args = self.parseArgs(argv)
        if args == None:
            message = '*** Error: parsing arguments!!'
            self.log_output('open ' + argv, message)
            return False
        numArgs = len(args)
        if numArgs == 1:
            fileName = args[0]
        elif numArgs == 2:
            fileName = args[1]
            args = args[0]
            if len(args) < 2 or len(args) > 3 or args[0] != '-' or args[1:] not in ['f','l','fl','lf']:
                self.help_open()
                return False
            if args.find('f') != -1:
                forceMode = True
            if args.find('l') != -1:
                looseMode = True
        else:
            self.help_open()
            return False
        if not os.path.exists(fileName):
            message = '*** Error: the file does not exist!!'
            self.log_output('open ' + argv, message)
            return False
            
        if self.pdfFile != None:
            del(self.pdfFile)
        pdfParser = PDFParser()
        ret = pdfParser.parse(fileName, forceMode, looseMode)
        if ret != -1:
            message = 'File open succesfully!!'
            self.pdfFile = ret[1]
        else:
            message = '*** Error: opening failed'
            self.pdfFile = None
        self.log_output('open ' + argv, message)
        if not JS_MODULE:
            print 'Warning: Spidermonkey is not installed!!'+newLine
        if self.pdfFile != None:
            self.do_info('')        

    def help_open(self):
        print newLine + 'Usage: open [-fl] filename' + newLine
        print 'Open and parse the specified file' + newLine
        print 'Options:'
        print '\t-f: Sets force parsing mode to ignore errors'
        print '\t-l: Sets loose parsing mode for problematic files' + newLine

    def do_quit(self, argv):
        return True
        
    def help_quit(self):
        print newLine + 'Usage: quit'
        print newLine + 'Exits from the console' + newLine
        
    def do_rawobject(self, argv):
        if self.pdfFile == None:
            message = '*** Error: You must open a file!!'
            self.log_output('rawobject ' + argv, message)
            return False
        compressed = False
        rawValue = ''
        offset = 0
        size = 0
        args = self.parseArgs(argv)
        if args == None:
            message = '*** Error: parsing arguments!!'
            self.log_output('rawobject ' + argv, message)
            return False
        if len(args) == 1:
            version = None
        elif len(args) == 2:
            version = args[1]
        else:
            self.help_rawobject()
            return False
        id = args[0]
        if (not id.isdigit() and id != 'trailer' and id != 'xref') or (version != None and not version.isdigit()):
            self.help_rawobject()
            return False
        if version != None:
            version = int(version)
            if version > self.pdfFile.getNumUpdates():
                message = '*** Error: the version number is not valid'
                self.log_output('rawobject ' + argv, message)
                return False
        if id == 'xref':
            ret = self.pdfFile.getXrefSection(version)
            if ret == None or ret[1] == None or ret[1] == [] or ret[1] == [None,None]:
                message = '*** Error: xref section not found!!'
                self.log_output('rawobject ' + argv, message)
                return False
            else:
                xrefArray = ret[1]
            if xrefArray[0] != None:
                offset = xrefArray[0].getOffset()
                size = xrefArray[0].getSize()
                rawValue = xrefArray[0].toFile()
        elif id == 'trailer':
            ret = self.pdfFile.getTrailer(version)
            if ret == None or ret[1] == None or ret[1] == [] or ret[1] == [None,None]:
                message = '*** Error: trailer not found!!'
                self.log_output('rawobject ' + argv, message)
                return False
            else:
                trailerArray = ret[1]
            if trailerArray[0] != None:
                offset = trailerArray[0].getOffset()
                size = trailerArray[0].getSize()
                rawValue = trailerArray[0].toFile()
        else:
            id = int(id)
            indirectObject = self.pdfFile.getObject(id, version, indirect = True)
            if indirectObject == None:
                message = '*** Error: object not found!!'
                self.log_output('rawobject ' + argv, message)
                return False
            object = indirectObject.getObject()
            compressed = object.isCompressed()
            offset = indirectObject.getOffset()
            size = indirectObject.getSize()
            rawValue = str(object.getRawValue())
        if offset == -1:
            message = '*** Error: offset cannot be calculated!!'
            self.log_output('rawobject ' + argv, message)
            return False
        '''
        # Getting the raw bytes directly from the file
        filePath = self.pdfFile.getPath()
        if not compressed and filePath != '' and os.path.exists(filePath):
            ret = getBytesFromFile(filePath,offset,size)
            if ret[0] == -1:
                message = '*** Error: the file does not exist!!'
                self.log_output('rawobject ' + argv, message)
                return False
            rawValue = ret[1]
        '''
        self.log_output('rawobject ' + argv, rawValue, storeOutput = True)
        
    def help_rawobject(self):
        print newLine + 'Usage: rawobject [object_id|xref|trailer [version]]'
        print newLine + 'Show the content of the object without being decoded or decrypted (object_id, xref, trailer)' + newLine

    def do_rawstream(self, argv):
        if self.pdfFile == None:
            message = '*** Error: You must open a file!!'
            self.log_output('rawstream ' + argv, message)
            return False
        args = self.parseArgs(argv)
        if args == None:
            message = '*** Error: parsing arguments!!'
            self.log_output('rawstream ' + argv, message)
            return False
        if len(args) == 1:
            version = None
        elif len(args) == 2:
            version = args[1]
        else:
            self.help_rawstream()
            return False
        id = args[0]
        if not id.isdigit() or (version != None and not version.isdigit()):
            self.help_rawstream()
            return False
        id = int(id)
        if version != None:
            version = int(version)
            if version > self.pdfFile.getNumUpdates():
                message = '*** Error: the version number is not valid'
                self.log_output('stream ' + argv, message)
                return False
        object = self.pdfFile.getObject(id, version)
        if object == None:
            message = '*** Error: object not found!!'
            self.log_output('stream ' + argv, message)
            return False
        if object.getType() != 'stream':
            message = '*** Error: The object doesn\'t contain any stream!!'
            self.log_output('rawstream ' + argv, message)
            return False
        value = object.getRawStream()
        self.log_output('rawstream ' + argv, value, storeOutput = True, bytesOutput = True)
    
    def help_rawstream(self):
        print newLine + 'Usage: rawstream object_id [version]'
        print newLine + 'Shows the stream content of the specified document version before being decoded and decrypted' + newLine
        
    def do_references(self,argv):
        if self.pdfFile == None:
            message = '*** Error: You must open a file!!'
            self.log_output('references ' + argv, message)
            return False
        args = self.parseArgs(argv)
        if args == None:
            message = '*** Error: parsing arguments!!'
            self.log_output('references ' + argv, message)
            return False
        if len(args) == 2:
            version = None
        elif len(args) == 3:
            version = args[2]
        else:
            self.help_references()
            return False
        command = args[0]
        id = args[1]
        if not id.isdigit() or (version != None and not version.isdigit()) or (command.lower() != 'to' and command.lower() != 'in'):
            self.help_references()
            return False
        id = int(id)
        if version != None:
            version = int(version)
            if version > self.pdfFile.getNumUpdates():
                message = '*** Error: the version number is not valid'
                self.log_output('references ' + argv, message)
                return False
        if command.lower() == 'to':
            references = self.pdfFile.getReferencesTo(id, version)
        else:
            references = self.pdfFile.getReferencesIn(id, version)
        if references == []:
            references = 'No references!!'
        elif references == None:
            references = '*** Error: Object not found!!'
        self.log_output('references ' + argv, str(references), storeOutput = True)
    
    def help_references(self):
        print newLine + 'Usage: references to|in object_id [version]'
        print newLine + 'Shows the references in the object or to the object in the specified version of the document' + newLine

    def do_replace(self, argv):
        replaceOutput = ''
        args = self.parseArgs(argv)
        if args == None:
            message = '*** Error: parsing arguments!!'
            self.log_output('replace ' + argv, message)
            return False
        numArgs = len(args)
        if numArgs != 3 and numArgs != 4:
            self.help_replace()
            return False
        type = args[0]
        if numArgs == 3:
            if type != 'all':
                self.help_replace()
                return False
            if self.pdfFile == None:
                message = '*** Error: You must open a file!!'
                self.log_output('replace ' + argv, message)
                return False
            string1 = args[1]
            string2 = args[2]
            ret = self.pdfFile.replace(string1, string2)
            if ret[0] == -1:
                if ret[1] == 'String not found':
                    message = 'String not found!!'
                else:
                    message = '*** Error: the string has not been replaced!!'
            else:
                message = 'The string has been replaced correctly'
        elif numArgs == 4:
            if type != 'variable' and type != 'file':
                self.help_replace()
                return False
            src = args[1]
            string1 = args[2]
            string2 = args[3]
            if type == 'file':
                if not os.path.exists(src):
                    message = '*** Error: the file does not exist!!'
                    self.log_output('replace ' + argv, message)
                    return False
                content = open(src,'r').read()
                if content.find(string1) != -1:
                    replaceOutput = content.replace(string1, string2)
                    try:
                        open(src,'w').write(replaceOutput)
                    except:
                        message = '*** Error: the file cannot be modified!!'
                        self.log_output('replace ' + argv, message)
                        return False
                    message = 'The string has been replaced correctly'
                else:
                    message = 'String not found!!'
            else:
                if self.variables.has_key(src):
                    if self.variables[src][0].find(string1) != -1:
                        replaceOutput = self.variables[src][0].replace(string1, string2)
                        self.variables[src][0] = replaceOutput
                        message = 'The string has been replaced correctly'
                    else:
                        message = 'String not found!!'
                else:
                    message = '*** Error: the variable does not exist!!'
        self.log_output('replace ' + argv, message)        
                
    def help_replace(self):
        print newLine + 'Usage: replace  all string1 string2'
        print newLine + 'Replace \'string1\' with \'string2\' in the whole PDF file' + newLine
        print 'Usage: replace variable var_name string1 string2'
        print 'Usage: replace file file_name string1 string2'
        print newLine + 'Replace \'string1\' with \'string2\' in the content of the specified variable or file' + newLine

    def do_reset(self, argv):
        args = self.parseArgs(argv)
        if args == None:
            message = '*** Error: parsing arguments!!'
            self.log_output('reset ' + argv, message)
            return False
        numArgs = len(args)
        if numArgs == 0:
            clearScreen()
        elif numArgs == 1:
            var = args[0]
            if self.variables.has_key(var):
                self.variables[var][0] = self.variables[var][1]
                message = var + ' = "' + self.variables[var][0] + '"'
            else:
                message = '*** Error: the variable does not exist!!'
            self.log_output('reset ' + argv, message)
        else:
            self.help_reset()
    
    def help_reset(self):
        print newLine + 'Usage: reset'
        print 'Cleans the console' + newLine
        print 'Usage: reset var_name'
        print newLine + 'Resets the variable value to the default value if applicable' + newLine
        
    def do_save(self, argv):
        if self.pdfFile == None:
            message = '*** Error: You must open a file!!'
            self.log_output('save ' + argv, message)
            return False
        args = self.parseArgs(argv)
        if args == None:
            message = '*** Error: parsing arguments!!'
            self.log_output('save ' + argv, message)
            return False
        numArgs = len(args)
        if numArgs == 0 or numArgs == 1:
            if numArgs == 0:
                fileName = self.pdfFile.getPath()
            else:
                fileName = args[0]
            ret = self.pdfFile.save(fileName, malformedOptions = self.variables['malformed_options'][0], headerFile = self.variables['header_file'][0])
            if ret[0] == -1:
                message = '*** Error: saving failed!!'            
            else:
                message = 'File saved succesfully!!'
            self.log_output('save ' + argv, message)
        else:
            self.help_save()

    def help_save(self):
        print newLine + 'Usage: save [filename]'
        print newLine + 'Saves the file to disk' + newLine
        
    def do_save_version(self, argv):
        if self.pdfFile == None:
            message = '*** Error: You must open a file!!'
            self.log_output('save_version ' + argv, message)
            return False
        args = self.parseArgs(argv)
        if args == None:
            message = '*** Error: parsing arguments!!'
            self.log_output('save_version ' + argv, message)
            return False
        numArgs = len(args)
        if numArgs == 2:
            version = args[0]
            fileName = args[1]
            if not version.isdigit():
                self.help_save_version()
                return False
            version = int(version)
            if version < 0 or version > self.pdfFile.getNumUpdates():
                message = '*** Error: the version number is not valid'
                self.log_output('save_version ' + argv, message)
                return False
            ret = self.pdfFile.save(fileName, version, malformedOptions = self.variables['malformed_options'][0], headerFile = self.variables['header_file'][0])
            if ret[0] == -1:
                message = '*** Error: saving failed'
            else:
                message = 'Version saved succesfully!!'
            self.log_output('save_version ' + argv, message)
        else:
            self.help_save_version()
    
    def help_save_version(self):
        print newLine + 'Usage: save_version num_version filename'
        print newLine + 'Saves the selected file version to disk' + newLine

    def do_sctest(self, argv):
        validTypes = ['variable','file','raw']
        bytes = ''
        src = ''
        offset = 0
        size = 0
        args = self.parseArgs(argv)
        if args == None:
            message = '*** Error: parsing arguments!!'
            self.log_output('sctest ' + argv, message)
            return False
        if len(args) < 2 or len(args) > 3 or (len(args) == 3 and args[0] != 'raw'):
            self.help_sctest()
            return False
        type = args[0]
        if type not in validTypes:
            self.help_sctest()
            return False
        if not self.variables.has_key('sctest') or not os.path.exists(str(self.variables['sctest'][0])):
            if os.path.exists('sctest'):
                sctestPath = os.path.abspath('sctest')
                self.variables['sctest'] = [sctestPath, sctestPath]
            elif os.path.exists('sctest.exe'):
                sctestPath = os.path.abspath('sctest.exe')
                self.variables['sctest'] = [sctestPath, sctestPath]
            else:
                message = '*** Error: The path for the sctest executable has not been defined correctly!!'
                self.log_output('sctest ' + argv, message)
                return False
        else:
            sctestPath = os.path.abspath(str(self.variables['sctest'][0]))
            self.variables['sctest'] = [sctestPath, sctestPath]
            
        if type == 'raw':
            if self.pdfFile == None:
                message = '*** Error: You must open a file!!'
                self.log_output('sctest ' + argv, message)
                return False
            offset = args[1]
            size = args[2]
            if not offset.isdigit() or not size.isdigit():
                message = '*** Error: The offset and the number of bytes must be integers!!'
                self.log_output('sctest ' + argv, message)
                return False
            offset = int(offset)
            size = int(size)
        else:
            src = args[1]
        
        if type == 'variable':
            if not self.variables.has_key(src):
                message = '*** Error: the variable does not exist!!'
                self.log_output('sctest ' + argv, message)
                return False
            else:
                bytes = self.variables[src][0]
        elif type == 'file':
            if not os.path.exists(src):
                message = '*** Error: the file does not exist!!'
                self.log_output('sctest ' + argv, message)
                return False
            else:
                bytes = open(src,'r').read()                
        else:
            ret = getBytesFromFile(self.pdfFile.getPath(),offset,size)
            if ret[0] == -1:
                message = '*** Error: the file does not exist!!'
                self.log_output('sctest ' + argv, message)
                return False
            bytes = ret[1]
            
        # Calling the sctest program (Not smart, true, but useful...)
        cmd = self.variables['sctest'][0] + ' -Ss 100000'
        p = subprocess.Popen(cmd, shell=True, bufsize=1024, stdout=subprocess.PIPE, stdin=subprocess.PIPE)
        p.stdin.write(bytes)
        p.stdin.close()
        output = p.stdout.read()
        p.stdout.close()
        p.wait()
        self.log_output('sctest ' + argv, output, storeOutput = True)
        
    def help_sctest(self):
        print newLine + 'Usage: sctest variable var_name'
        print 'Usage: sctest file file_name'
        print 'Usage: sctest raw offset num_bytes'
        print newLine + 'Wrapper of the sctest tool (libemu) to emule shellcodes' + newLine

    def do_search(self, argv):
        if self.pdfFile == None:
            message = '*** Error: You must open a file!!'
            self.log_output('search ' + argv, message)
            return False
        output = ''
        args = self.parseArgs(argv)
        if args == None:
            message = '*** Error: parsing arguments!!'
            self.log_output('search ' + argv, message)
            return False
        if len(args) != 1 and len(args) != 2:
            self.help_search()
            return False
        if len(args) == 1:
            toSearch = args[0]
        elif len(args) == 2:
            if args[0] != 'hex':
                self.help_search()
                return False
            else:
                toSearch = args[1]
                if re.match('(\\\\x[0-9a-f]{1,2})+',toSearch):
                    hexChars = toSearch.split('\\x')
                    hexChars.remove('')
                    toSearch = ''
                    for hexChar in hexChars:
                        if len(hexChar) == 1:
                            hexChar = '0'+hexChar
                        toSearch += hexChar
                    ret = hexToString(toSearch)
                    if ret[0] == -1:
                        message = '*** Error: '+ret[1]+'!!'
                        self.log_output('search ' + argv, message)
                        return False
                    toSearch = ret[1]
                else:
                    message = '*** Error: bad hexadecimal string!!'
                    self.log_output('search ' + argv, message)
                    return False
        toSearch = escapeRegExpString(toSearch)
        objects = self.pdfFile.getObjectsByString(toSearch)
        if objects == []:
            output = 'Not found!!'
        else:
            if len(objects) == 1:
                if objects[0] == []:
                    output = 'Not found!!'
                else:
                    output = str(objects[0])
            else:
                for version in range(len(objects)):
                    if objects[version] != []:
                        output += newLine + str(version) + ': '+ str(objects[version]) + newLine
                if output == '':
                    output = 'Not found!!'
                else:
                    output = output[1:-1]
        self.log_output('search ' + argv, output, storeOutput = True)
        
    def help_search(self):
        print newLine + 'Usage: search [hex] string'
        print newLine + 'Search the specified string or hexadecimal string in the objects (decoded and encrypted streams included)' + newLine
        print 'Example: search hex \\x34\\x35' + newLine
    
    def do_set(self, argv):
        consoleOutput = ''
        args = self.parseArgs(argv)
        if args == None:
            message = '*** Error: parsing arguments!!'
            self.log_output('set ' + argv, message)
            return False
        numArgs = len(args)
        if numArgs != 0 and numArgs != 2 and numArgs != 3:
            self.help_set()
            return False
        if numArgs == 0:
            vars = self.variables.keys()
            for var in vars:
                if var == 'output' and (self.variables[var][0] == 'file' or self.variables[var][0] == 'variable'):
                    consoleOutput += var + ' = "' + self.output + '" ('+ str(self.variables[var][0]) +')' + newLine
                else:
                    varContent = self.printResult(str(self.variables[var][0]))
                    if varContent == str(self.variables[var][0]):
                        if varContent != 'None' and not re.match('\[.*\]',varContent):
                            consoleOutput += var + ' = "' + varContent + '"' + newLine
                        else:
                            consoleOutput += var + ' = ' + varContent + newLine
                    else:
                        consoleOutput += var + ' = ' + newLine + varContent + newLine
            print newLine + consoleOutput
        else:
            varName = args[0]
            value = args[1]
            if varName == 'output':
                if value not in self.validVariableValues[varName]:
                    self.help_set()
                    return False
                if value != 'stdout':
                    if numArgs != 3:
                        self.help_set()
                        return False
                    else:
                        self.variables[varName][0] = value
                        self.output = args[2]
                else:
                    if numArgs != 2:
                        self.help_set()
                        return False
                    else:
                        self.variables[varName][0] = value
                        self.output = None
            else:
                if varName in self.readOnlyVariables:
                    message = '*** Error: this is a READ ONLY variable!!'
                    self.log_output('set ' + argv, message)
                    return False
                if varName == 'output_limit' and not value.isdigit():
                    message = '*** Error: the value for this variable must be an integer!!'
                    self.log_output('set ' + argv, message)
                    return False
                if self.variables.has_key(varName):
                    self.variables[varName][0] = value
                else:
                    self.variables[varName] = [value, value]
                
    def help_set(self):
        print newLine + 'Usage: set [var_name var_value]'
        print newLine + 'Sets the specified variable value or creates one with this value. Without parameters all the variables are shown.' + newLine
        print 'Special variables:' + newLine
        print '\theader_file: READ ONLY. Specifies the file header to be used when \'malformed_options\' are active.' + newLine
        print '\tmalformed_options: READ ONLY. Variable to store the malformed options used to save the file.' + newLine
        print '\toutput: specifies the destination of the commands output. Valid values are: \'stdout\', \'variable\' and \'file\'.' + newLine
        print '\toutput_limit: variable to specify the maximum number of lines to be shown at once when the output is long. By default there is no limit.' + newLine
        print '\tsctest: path of the sctest binary. If not specified the working directory will be the default path.' + newLine
        print '\tUsage for the \'output\' variable:' + newLine 
        print '\t> set output stdout'
        print '\tNormal console output' + newLine
        print    '\t> set output file file_name'
        print '\tStores the results of the commands in the specified file' + newLine
        print    '\t> set output variable var_name'
        print '\tStores the results of the commands in the specified variable' + newLine

    def do_show(self, argv):
        args = self.parseArgs(argv)
        if args == None:
            message = '*** Error: parsing arguments!!'
            self.log_output('show ' + argv, message)
            return False
        if len(args) != 1:
            self.help_show()
            return False
        var = args[0]
        if not self.variables.has_key(var):
            print newLine + '*** Error: the variable ' + var + ' does not exist!!' + newLine
            return False
        if var == 'output':
            if self.variables[var][0] == 'stdout':
                print newLine + 'output = "stdout"' + newLine
            else:
                if self.variables[var][0] == 'file':
                    print newLine + 'output = "file"'
                    print 'fileName = "'+self.output+'"' + newLine
                else:
                    print newLine + 'output = "variable"'
                    print 'varName = "'+self.output+'"' + newLine
        else:
            varContent = self.printResult(str(self.variables[var][0]))
            print newLine + varContent + newLine
        
    def help_show(self):
        print newLine + 'Usage: show var_name'
        print newLine + 'Shows the value of the specified variable' + newLine
        print 'Special variables:' + newLine
        print '\theader_file'
        print '\tmalformed_options'
        print '\toutput'
        print '\toutput_limit'
        print '\tsctest' + newLine

    def do_stream(self, argv):
        if self.pdfFile == None:
            message = '*** Error: You must open a file!!'
            self.log_output('stream ' + argv, message)
            return False
        result = ''
        args = self.parseArgs(argv)
        if args == None:
            message = '*** Error: parsing arguments!!'
            self.log_output('stream ' + argv, message)
            return False
        if len(args) == 1:
            version = None
        elif len(args) == 2:
            version = args[1]
        else:
            self.help_stream()
            return False
        id = args[0]
        if not id.isdigit() or (version != None and not version.isdigit()):
            self.help_stream()
            return False
        id = int(id)
        if version != None:
            version = int(version)
            if version > self.pdfFile.getNumUpdates():
                message = '*** Error: the version number is not valid'
                self.log_output('stream ' + argv, message)
                return False
        object = self.pdfFile.getObject(id, version)
        if object == None:
            message = '*** Error: object not found!!'
            self.log_output('stream ' + argv, message)
            return False
        if object.getType() != 'stream':
            message = '*** Error: The object doesn\'t contain any stream!!'
            self.log_output('stream ' + argv, message)
            return False
        value = object.getStream()
        if value == -1:
            message = '*** Error: The stream cannot be decoded!!'
            self.log_output('stream ' + argv, message)
            return False
        self.log_output('stream ' + argv, value, storeOutput = True, bytesOutput = True)
            
    def help_stream(self):
        print newLine + 'Usage: stream object_id [version]'
        print newLine + 'Shows the object stream content of the specified version after being decoded and decrypted (if necessary)' + newLine


    def do_tree(self, argv):
        if self.pdfFile == None:
            message = '*** Error: You must open a file!!'
            self.log_output('version ' + argv, message)
            return False
        version = None
        treeOutput = ''
        tree = []
        args = self.parseArgs(argv)
        if args == None:
            message = '*** Error: parsing arguments!!'
            self.log_output('tree ' + argv, message)
            return False
        numArgs = len(args)
        if numArgs == 0:
            tree = self.pdfFile.getTree()
        elif numArgs == 1:
            version = args[0]
            if version != None and not version.isdigit():
                message = '*** Error: the version number is not valid'
                self.log_output('tree ' + argv, message)
                return False
            version = int(version)
            if version > self.pdfFile.getNumUpdates() or version < 0:
                message = '*** Error: the version number is not valid'
                self.log_output('tree ' + argv, message)
                return False
            tree = self.pdfFile.getTree(version)
        else:
            self.help_tree()
            return False
        for i in range(len(tree)):
            nodesPrinted = []
            root = tree[i][0]
            objectsInfo = tree[i][1]
            if i != 0:
                treeOutput += newLine + 'Version '+str(i)+':' + newLine*2
            if root != None:
                nodesPrinted, nodeOutput = self.printTreeNode(root, objectsInfo, nodesPrinted)
                treeOutput += nodeOutput
            for object in objectsInfo:
                nodesPrinted, nodeOutput = self.printTreeNode(object, objectsInfo, nodesPrinted)
                treeOutput += nodeOutput
        self.log_output('tree ' + argv, treeOutput, storeOutput = True)
                    
    def help_tree(self):
        print newLine + 'Usage: tree [num_version]'
        print newLine + 'Shows the tree graph of the file or specified version' + newLine
        
    def additionRequest(self, dict = False):
        '''
            Method to ask the user if he want to add more entries to the object or not
            @param dict Boolean to specify if the added object is a dictionary or not. Default value: False.
            @return The response chosen by the user
        '''
        if not dict:
            message = newLine + 'Do you want to add more objects? (y/n) '
        else:
            message = newLine + 'Do you want to add more entries? (y/n) '
        res = raw_input(message)
        if res.lower() in ['y','n']:
            return res.lower()
        else:
            return None
                    
    def addObject(self, iteration, maxDepth = 10):
        '''
            Method to add a new object to an array or dictionary
            @param iteration Integer which specifies the depth of the recursion in the same object
            @param maxDepth The maximum depth for nested objects. Default value: 10.
            @return The new object
        '''
        dictNumType = {'1':'boolean','2':'number','3':'string','4':'hexstring','5':'name','6':'reference','7':'null','8':'array','9':'dictionary'}
        if iteration > maxDepth:
            return (-1,'Object too nested!!')
        message = 'What type of object do you want to include? (1-9)' + newLine+\
                    '\t1 - boolean' + newLine+\
                    '\t2 - number' + newLine+\
                    '\t3 - string' + newLine+\
                    '\t4 - hexstring' + newLine+\
                    '\t5 - name' + newLine+\
                    '\t6 - reference' + newLine+\
                    '\t7 - null' + newLine+\
                    '\t8 - array' + newLine+\
                    '\t9 - dictionary' + newLine
        res = raw_input(message)
        if not res.isdigit() or int(res) < 1 or int(res) > 9:
            return (-1,'Object type not valid!!')
        objectType = dictNumType[res]
        if objectType != 'array' and objectType != 'dictionary':
            content = raw_input(newLine + 'Please, specify the '+objectType+' object content:' + newLine*2)
            content = self.checkInputContent(objectType, content) 
            if content == None:
                return (-1, '*** Error: content not valid for the object type!!')
        if objectType == 'boolean':
            object = PDFBool(content)
        elif objectType == 'number':
            object = PDFNum(content)
        elif objectType == 'string':
            object = PDFString(content)
        elif objectType == 'hexstring':
            object = PDFHexString(content)
        elif objectType == 'name':
            object = PDFName(content)
        elif objectType == 'reference':
            contentElements = content.split()
            id = contentElements[0]
            genNum = contentElements[1]
            object = PDFReference(id,genNum)
        elif objectType == 'null':
            object = PDFNull(content)
        elif objectType == 'array':
            elements = []
            print 'Please, now specify the elements of the array:'
            while True:
                res = self.additionRequest()
                if res == None:
                    return (-1,'Option not valid!!')
                elif res == 'y':
                    ret = self.addObject(iteration+1)
                    if ret[0] == -1:
                        return ret
                    elements.append(ret[1])
                else:
                    break
            object = PDFArray(elements = elements)
        elif objectType == 'dictionary':
            elements = {}
            print 'Please, now specify the elements of the dictionary:'
            while True:
                res = self.additionRequest(dict = True)
                if res == None:
                    return (-1,'Option not valid!!')
                elif res == 'y':
                    key = raw_input('Name object: ')
                    key = self.checkInputContent('name', key)
                    ret = self.addObject(iteration+1)
                    if ret[0] == -1:
                        return ret
                    elements[key] = ret[1]
                else:
                    break
            object = PDFDictionary(elements = elements)
        return (0,object)

    def checkInputContent(self, objectType, objectContent):
        '''
            Check if the specified content is valid for the specified object type and modify it\'s possible
            @param objectType The type of object: number, string, hexstring, name, reference, null
            @param objectContent The object content
            @return The content of the object or None if any problems occur
        '''
        spacesChars = ['\x00','\x09','\x0a','\x0c','\x0d','\x20']
        demilimiterChars = ['<<','(','<','[','{','/','%']
        if objectType == 'bool':
            if objectContent.lower() not in ['true','false']:
                return None
            else:
                objectContent = objectContent.lower()
        elif objectType == 'number':
            try:
                if objectContent.find('.') != -1:
                    float(objectContent)
                else:
                    int(objectContent)
            except:
                return None
        elif objectType == 'string':
            octalNumbers = re.findall('\\\\(\d{1,3})', objectContent, re.DOTALL)
            for octal in octalNumbers:
                try:
                    chr(int(octal,8))
                except:
                    return None
        elif objectType == 'hexstring':
            objectContent = objectContent.replace('<','')
            objectContent = objectContent.replace('>','')
            for i in range(0,len(objectContent),2):
                try:
                    chr(int(objectContent[i:i+2],16))
                except:
                    return None
        elif objectType == 'name':
            if objectContent[0] == '/':
                objectContent = objectContent[1:]
            for char in objectContent:
                if char in spacesChars+demilimiterChars:
                    return None
            hexNumbers = re.findall('#([0-9a-f]{2})', objectContent, re.DOTALL | re.IGNORECASE)
            for hexNumber in hexNumbers:
                try:
                    chr(int(hexNumber,16))
                except:
                    return None
            objectContent = '/'+objectContent
        elif objectType == 'reference':
            if not re.match('\d{1,10}\s\d{1,10}\sR',objectContent,re.IGNORECASE):
                return None
            objectContent = objectContent.replace('r','R')
        elif objectType == 'null':
            if objectContent.lower() != 'null':
                return None
            else:
                objectContent = objectContent.lower()
        return objectContent

    def log_output(self, command, output, bytes = None, printOutput = True, storeOutput = False, bytesOutput = False):
        '''
            Method to check the commands output and write it to the console and/or files
            @param command The command launched
            @param output The output of the command
            @param bytes The raw bytes of the command
            @param printOutput Boolean to specify if the output will be written to the console or not. Default value: True.
            @param storeOutput Boolean to specify if the output will be stored in a variable or file. Default value: False.
            @param bytesOutput Boolean to specify if the raw bytes of output will be stored or not. Default value: False.
            @return 
        '''
        if bytesOutput and output != '':
            niceOutput = self.printResult(output)
        else:
            niceOutput = output
        niceOutput = niceOutput.strip(newLine)
        niceOutput = niceOutput.replace('\r\n','\n')
        niceOutput = niceOutput.replace('\r','\n')
        longOutput = command + newLine * 2 + niceOutput + newLine * 2
        if self.loggingFile != None:
            open(self.loggingFile,'a').write(self.prompt+longOutput)
        if storeOutput:
            if bytes != None:
                output = bytes
            if self.variables['output'][0] == 'file':
                open(self.output,'a').write(output)
            elif self.variables['output'][0] == 'variable':
                if self.variables.has_key(self.output):
                    self.variables[self.output][0] = output
                else:
                    self.variables[self.output] = [output,output]
        if printOutput:
            niceOutput = newLine + niceOutput + newLine
            if self.variables['output_limit'][0] == None or not self.use_rawinput:
                print niceOutput
            else:
                limit = int(self.variables['output_limit'][0])
                lines = niceOutput.split(newLine)
                while len(lines) > 0:
                    outputStepLines = lines[:limit]
                    lines = lines[limit:]
                    for line in outputStepLines:
                        print line
                    raw_input('( Press <intro> to continue )')
            

    def modifyObject(self, object, iteration = 0, contentFile = None, maxDepth = 10):
        '''
            Method to modify an existen object
            @param object The object to be modified
            @param iteration Integer which specifies the depth of the recursion in the same object
            @param contentFile The content of the file storing the stream
            @param maxDepth The maximum depth for nested objects. Default value: 10.
            @return The new object
        '''
        if iteration > maxDepth:
            return (-1,'Object too nested!!')
        objectType = object.getType()
        newObjectType = objectType
        if objectType != 'array' and objectType != 'stream' and objectType != 'dictionary':
            if contentFile != None and iteration == 0:
                content = open(contentFile,'r').read()
            else:
                if objectType == 'string' or objectType == 'hexstring':
                    res = raw_input(newLine + 'Do you want to enter an ascii (1) or hexadecimal (2) string? (1/2) ')
                    if res == '1':
                        newObjectType = 'string'
                    elif res == '2':
                        newObjectType = 'hexstring'
                    else:
                        return (-1,'*** Error: the string type is not valid')
                elif objectType == 'integer' or objectType == 'real':
                    newObjectType = 'number'
                if iteration == 0:
                    content = raw_input(newLine + 'Please, specify the '+newObjectType+' object content (if the content includes EOL characters use a file instead):' + newLine*2)
                else:
                    value = object.getValue()
                    rawValue = str(object.getRawValue())
                    res = self.modifyRequest(value, rawValue)
                    if res == 'd':
                        return (0,None)
                    elif res == 'm':
                        content = raw_input(newLine + 'Please, specify the '+newObjectType+' object content:' + newLine*2)
                    else:
                        return (0,object)
                content = self.checkInputContent(newObjectType, content)
                if content == None:
                    return (-1, '*** Error: content not valid for the object type!!')
                if newObjectType != objectType:
                    if newObjectType == 'string':
                        object = PDFString(content)
                    elif newObjectType == 'hexstring':
                        object = PDFHexString(content)
                    elif newObjectType == 'number':
                        object.setValue(content)
                else:
                    object.setRawValue(content)
        else:
            if objectType == 'array':
                newElements = []
                elements = object.getElements()
                for element in elements:
                    ret = self.modifyObject(element,iteration+1,maxDepth=maxDepth)
                    if ret[0] == -1:
                        return ret
                    else:
                        newObject = ret[1]
                        if newObject != None:
                            newElements.append(newObject)
                while True:
                    res = self.additionRequest()
                    if res == None:
                        return (-1,'Option not valid!!')
                    elif res == 'y':
                        ret = self.addObject(iteration+1)
                        if ret[0] == -1:
                            return ret
                        newElements.append(ret[1])
                    else:
                        break
                object.setElements(newElements)
            elif objectType == 'dictionary' or objectType == 'stream':
                newElements = {}
                elements = object.getElements()
                if objectType == 'stream':
                    if iteration == 0:
                        value = object.getStream()
                        rawValue = ''
                        ret = self.modifyRequest(value, rawValue, stream = True)
                        if ret == 'd':
                            object.setDecodedStream('')
                        elif ret == 'm':
                            if contentFile != None:
                                streamContent = open(contentFile,'r').read()
                            else:
                                streamContent = raw_input(newLine + 'Please, specify the stream content (if the content includes EOL characters use a file instead):' + newLine*2)
                            object.setDecodedStream(streamContent)
                    else:
                        return (-1,'Nested streams are not permitted!!')
                for element in elements:
                    valueObject = elements[element]
                    value = valueObject.getValue()
                    rawValue = valueObject.getRawValue()
                    ret = self.modifyRequest(value, rawValue, element)
                    if ret == 'n':
                        newElements[element] = valueObject
                    elif ret == 'm':
                        nestRet = self.modifyObject(valueObject,iteration+1,maxDepth=maxDepth)
                        if nestRet[0] == -1:
                            return nestRet
                        else:
                            newObject = nestRet[1]
                            newElements[element] = newObject
                while True:
                    res = self.additionRequest(dict = True)
                    if res == None:
                        return (-1,'Option not valid!!')
                    elif res == 'y':
                        key = raw_input('Name object: ')
                        key = self.checkInputContent('name', key)
                        ret = self.addObject(iteration+1)
                        if ret[0] == -1:
                            return ret
                        newElements[key] = ret[1]
                    else:
                        break
                object.setElements(newElements)
        return (0,object)
                        
    def modifyRequest(self, value, rawValue, key = None, stream = False):
        '''
            Method to ask the user what he wants to do with the object: modify, delete or nothing.
            @param value The value of the object.
            @param rawValue The raw value of the object.
            @param key The key of a dictionary entry.
            @param stream Boolean to specify if the object contains a stream or not.
            @return The response chosen by the user
        '''
        message = ''
        if not stream:
            message = newLine
            if key != None:
                message += 'Key: '+key+newLine
            message += 'Raw value: '+str(rawValue)+newLine
            if rawValue != value:
                message += 'Value: '+str(value)+newLine
        message += newLine + 'Do you want to modify, delete or make no action'
        if stream:
            message += ' in the STREAM'
        message += '? (m/d/n) '
        response = raw_input(message)
        if response.lower() not in ['m','d','n']:
            return None
        else:
            if stream and response.lower() == 'm':
                print 'Value: '+str(value)+newLine
            return response.lower()
        
    def parseArgs(self,args):
        '''
            Method to split up the command arguments by quotes: \'\'\', " or \'
            @param args The command arguments
            @return An array with the separated arguments
        '''
        argsArray = []
        while len(args) > 0:
            if args[0] == '\'':
                if args[:3] == '\'\'\'':
                    index = args[3:].find('\'\'\'')
                    if index != -1:
                        arg = args[3:index+3]
                        argsArray.append(arg)
                        if len(args) > index + 6:
                            args = args[index+6:]
                        else:
                            args = ''
                    else:
                        return None
                else:
                    index = args[1:].find('\'')
                    if index != -1:
                        arg = args[1:index+1]
                        argsArray.append(arg)
                        if len(args) > index + 2:
                            args = args[index+2:]
                        else:
                            args = ''
                    else:
                        return None
            elif args[0] == '"':
                index = args[1:].find('"')
                if index != -1:
                    arg = args[1:index+1]
                    argsArray.append(arg)
                    if len(args) > index + 2:
                        args = args[index+2:]
                    else:
                        args = ''
                else:
                    return None
            elif args[0] == ' ':
                args = args[1:]
            else:
                index = args.find(' ')
                if index != -1:
                    arg = args[:index]
                    argsArray.append(arg)
                    if len(args) > index + 1:
                        args = args[index+1:]
                    else:
                        args = ''
                else:
                    argsArray.append(args)
                    args = ''
        return argsArray
        
    def printBytes(self, bytes):
        '''
            Given a byte string shows the hexadecimal and ascii output in a nice way
            @param unescapedBytes
            @return String with mixed hexadecimal and ascii strings, like the 'hexdump -C' output
        '''
        output = ''
        row = 16
        if bytes != '':
            i = None
            hexChain = ''
            strings = ''
            for i in range(0,len(bytes)):
                if ord(bytes[i]) > 31 and ord(bytes[i]) < 128:
                    strings += bytes[i]
                else:
                    strings += '.'
                hexChars = hex(ord(bytes[i]))
                hexChars = hexChars[2:]
                if len(hexChars) == 1:
                    hexChars = '0' + hexChars
                hexChain += hexChars + ' '
                if i != 0 and i % row == row -1:
                    output += hexChain + '  |' + strings + '|' + newLine
                    hexChain = ''
                    strings = ''
            if i != None and i % row != 0:
                if hexChain == '':
                    output = output[:-1]
                else:
                    output += hexChain + (48 - len(hexChain))*' ' + '  |' + strings + '|'
        return output
       
    def printResult(self, result):
        '''
            Given an string returns a mixed hexadecimal-ascci output if there are many non printable characters or the same string in other case
            @param result (string)
            @return A mixed hexadecimal-ascii output if there are many non printable characters or the input string in other case
        '''
        size = len(result)
        num = countNonPrintableChars(result)
        if size/2 < num:
            return self.printBytes(result)
        else:
            return result
    
    def printTreeNode(self, node, nodesInfo, expandedNodes = [], depth = 0, recursive = True):
        '''
            Given a tree prints the whole tree and its dependencies
            @param node Root
            @param nodesInfo
            @param expandedNodes
            @param depth
            @param recurisve
            @return A tuple (expandedNodes,output), where expandedNodes is a list with the distinct nodes and output is the string representation of the tree
        '''
        output = ''
        if nodesInfo.has_key(node):
            if node not in expandedNodes or (node in expandedNodes and depth > 0):
                output += '\t'*depth + nodesInfo[node][0] + ' (' +str(node) + ')' + newLine
            if node not in expandedNodes:
                expandedNodes.append(node)
                children = nodesInfo[node][1]
                if children != []:
                    for child in children:
                        if nodesInfo.has_key(child):
                            childType = nodesInfo[child][0]
                        else:
                            childType = 'Unknown'
                        if childType != 'Unknown' and recursive:
                            expChildrenNodes, childrenOutput = self.printTreeNode(child, nodesInfo, expandedNodes, depth+1)
                            output += childrenOutput
                            expandedNodes = expChildrenNodes
                        else:
                            output += '\t'*(depth+1) + childType + ' (' +str(child) + ')' + newLine        
                else:
                    return expandedNodes,output
        return expandedNodes,output