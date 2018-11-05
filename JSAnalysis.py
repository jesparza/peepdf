#
#    peepdf is a tool to analyse and modify PDF files
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
    This module contains some functions to analyse Javascript code inside the PDF file
'''

import jsbeautifier
import os
import re
import sys
import traceback
import xml.dom.minidom
import subprocess
from subprocess import PIPE
import random
import string
from PDFUtils import unescapeHTMLEntities, escapeString

try:
    import PyV8
    
    JS_MODULE = True
    
    class Global(PyV8.JSClass):
        evalCode = ''
        
        def evalOverride(self, expression):
            self.evalCode += '\n\n// New evaluated code\n' + expression
            return
        
except:
    JS_MODULE = False


errorsFile = 'errors.txt'
newLine = os.linesep         
reJSscript = '<script[^>]*?contentType\s*?=\s*?[\'"]application/x-javascript[\'"][^>]*?>(.*?)</script>'
preDefinedCode = 'var app = this;'

def JSUnpack(code,rawCode,infoObjects,manualAnalysis=False):
    '''
    Hooks the eval function with multiple app versions and search for obfuscated elements in the Javascript code.
    Also take data from XFA, object info and getAnnot(s) in a PDF to an original code. The idea is mainly taken from JSUnpack
    
    @param code: the Javascript code (string)
    @param rawCode: The raw Javascript code, may contains HTML, XML elements (string)
    @param infoObjects: is list of infoObjects of a PDF
    @param manualAnalysis: analyse manually or automatic (boolean)
    @return: List with analysis information of the Javascript code: [JSCode,unescapedBytes,urlsFound,errors], where 
            JSCode is a list with the several stages Javascript code,
            unescapedBytes is a list with the parameters of unescape functions, 
            urlsFound is a list with the URLs found in the unescaped bytes,
            errors is a list of errors,
    '''
 
    # a dictionary for each app.viewerversion. Each element contains 4 lists: jsCode, unescapedBytes, urlsFound
    valuesFoundByViewerVersion={}
    #pre-code with data from inforamtion object
    preInfo=''
    #Take variable name(s) of xml elements (.e.g in XFA, Acroform)
    XMLVar=''
    #Build page tree and annotation data
    preAnnot=''
    #version strings
    pdfVersions = ['7.0','8.0','9.1']

    #get preInfo from InfoObject
    for obj in infoObjects:
        elements=obj.getElements()
        if elements.has_key("/Creator"):
            creatorValue=elements["/Creator"].getValue()
            preInfo +='info.creator = String("%s");\n' % (str(creatorValue))
            preInfo +="this.creator = info.creator;\n"
            preInfo +="info.Creator = info.creator;\n"
            preInfo +="app.doc.creator = info.creator;\n"
            preInfo +="app.doc.Creator = info.creator;\n"
        if elements.has_key("/Title"):
            titleValue=elements["/Title"].getValue()
            preInfo +='info.title = string("%s");\n' % (str(titleValue))
            preInfo +="this.title = info.title;\n"
            preInfo +="info.Title = info.title;\n"
            preInfo +="app.doc.title = info.title;\n"
            preInfo +="app.doc.Title = info.title;\n"
        if elements.has_key("/Subject"):
            subjectValue=elements["/Subject"].getValue()
            preInfo +='info.subject = String("%s");\n' % (str(subjectValue))
            preInfo +="this.subject = info.subject;\n"
            preInfo +="info.Subject = info.subject;\n"
            preInfo +="app.doc.subject = info.subject;\n"
            preInfo +="app.doc.Subject = info.subject;\n"
        if elements.has_key("/Author"):
            authorValue=elements["/Author"].getValue()
            preInfo +='info.author = String("%s");\n' % (str(authorValue))
            preInfo +="this.author = info.author;\n"
            preInfo +="info.Author = info.author;\n"
            preInfo +="app.doc.author = info.author;\n"
            preInfo +="app.doc.Author = info.author;\n"
        if elements.has_key("/CreationDate"):
            dateValue=elements["/CreationDate"].getValue()
            preInfo +='info.creationdate = String("%s");\n' % (str(dateValue))
            preInfo +="this.creationdate = info.creationdate;\n"
            preInfo +="info.CreationDate = info.creationdate;\n"
            preInfo +="app.doc.creationdate = info.creationdate;\n"
            preInfo +="app.doc.CreationDate = info.creationdate;\n"
            preInfo +="app.doc.creationDate = info.creationdate;\n"
            preInfo +="info.creationDate = info.creationdate;\n"

    #Get xml variable name
    try:
        doc = xml.dom.minidom.parseString(rawCode)
        scriptElements = doc.getElementsByTagNameNS("*", "script")
        if scriptElements:
            for script in scriptElements:
                nameVar= script.parentNode.parentNode.getAttribute('name')
                if nameVar:
                    XMLVar += nameVar + " = this;\n"
    
    except Exception as e:
        pass
    
    #Pre-process input code, same as in analyseJS
    try:
        code = unescapeHTMLEntities(code)
        scriptElements = re.findall(reJSscript, code, re.DOTALL | re.IGNORECASE)
        if scriptElements:
            code = ''
            for scriptElement in scriptElements:
                code += scriptElement + '\n\n'
        code = jsbeautifier.beautify(code)
        
        if code is not None and not manualAnalysis:
            originalCode = code
            for version in pdfVersions:
                # initialize 4 lists for each PDF version
                errors = []
                jsCode = []
                unescapedBytes = []
                urlsFound = []
                
                code = originalCode
                jsCode.append(code)
                viewerVersion='app.viewerVersion = Number(%s);\n' % (version)
                while True:
                    # test where processing code is a Javascript
                    isJS = isJavascript(code)
                    if isJS:
                        code = viewerVersion + preInfo + XMLVar + code

                    #Detect shellcode in code
                    if code != '':
                        #Detect shellcode and embedded URL(s) in case of using unescape function. e.g. x = unescape(%u0A0A%0B0B)
                        escapedVars = re.findall('(\w*?)\s*?=\s*?(unescape\((.*?)\))', code, re.DOTALL)
                        for var in escapedVars:
                            bytes = var[2]
                            if bytes.find('+') != -1 or bytes.find('%') == -1:
                                varContent = getVarContent(code, bytes)
                                if len(varContent) > 150:
                                    ret = unescape(varContent)
                                    if ret[0] != -1:
                                        bytes = ret[1]
                                        urls = re.findall('https?://.*$', bytes, re.DOTALL)
                                        if bytes not in unescapedBytes:
                                            unescapedBytes.append(bytes)
                                        for url in urls:
                                            if url not in urlsFound:
                                                urlsFound.append(url)
                            else:
                                bytes = bytes[1:-1]
                                if len(bytes) > 150:
                                    ret = unescape(bytes)
                                    if ret[0] != -1:
                                        bytes = ret[1]
                                        urls = re.findall('https?://.*$', bytes, re.DOTALL)
                                        if bytes not in unescapedBytes:
                                            unescapedBytes.append(bytes)
                                        for url in urls:
                                            if url not in urlsFound:
                                                urlsFound.append(url)
                        # Detect shellcode in case of finding variable assigned to an escaped string
                        # post.js produce a signature. e.g. #//shellcode len 767 (including any NOPs) payload = %u0A0A%u0A0A%u0A0A%uE1D9%u34D9%u5824%u5858
                        escapedVars = re.findall('//shellcode (pdf|len) (\d+) .*? = (.*)$', code,re.DOTALL)
                        for var in escapedVars:
                            bytes = str(var[2])
                            if len(bytes) > 150:
                                ret = unescape(bytes)
                                if ret[0] != -1:
                                    bytes = ret[1]
                                    urls = re.findall('https?://.*$', bytes, re.DOTALL)
                                    if bytes not in unescapedBytes:
                                        unescapedBytes.append(bytes)
                                    for url in urls:
                                        if url not in urlsFound:
                                            urlsFound.append(url)


                    #Hook eval and run Javascript
                    if isJS:
                        status,evalCode,error = evalJS(code)
                        evalCode = jsbeautifier.beautify(evalCode)
                        if error != "":
                            errors.append(error)

                        #if next stage of the JS exists, re-eval the next stage
                        if (evalCode is not None or evalCode != '') and evalCode != code:
                            # Assign code to the next stage
                            code = evalCode
                            if isJavascript(code):
                                jsCode.append(code)
                        else:
                            break
                    else:
                        break
                valuesFoundByViewerVersion[version]=[jsCode,unescapedBytes,urlsFound,errors]
    except:
        traceback.print_exc(file=open(errorsFile, 'a'))
        errors.append('Unexpected error in the JSUnpack module!!')

    return valuesFoundByViewerVersion

def evalJS(code):
    """
    @param code: the Javascript code
    @return: a set of status, eval code, error
    """
    try: 
        fileNameJS = randomString(10) + ".js.tmp"
        # Create temporal JS file
        with open(fileNameJS,'w') as fileJS:
            fileJS.write(code)
        # Use Google V8 Java interpreter, however, SpiderMoney should generate same results
        po = subprocess.Popen(['v8', '-f', 'pre.js', '-f', fileNameJS , '-f', 'post.js'],shell=False, stdout=PIPE, stderr=PIPE)
        return (0,po.stdout.read(),po.stderr.read())
    except:
        error = str(sys.exc_info()[1])
        open('jserror.log', 'ab').write(error + newLine)
        return (1,"",error)
    finally:
        # Remove temporal JS file
        os.remove(fileNameJS)
            
def randomString(stringLength=10):
    """Generate a random string of fixed length """
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(stringLength))

def analyseJS(code, context=None, manualAnalysis=False):
    '''
        Hooks the eval function and search for obfuscated elements in the Javascript code
        
        @param code: The Javascript code (string)
        @return: List with analysis information of the Javascript code: [JSCode,unescapedBytes,urlsFound,errors,context], where 
                JSCode is a list with the several stages Javascript code,
                unescapedBytes is a list with the parameters of unescape functions, 
                urlsFound is a list with the URLs found in the unescaped bytes,
                errors is a list of errors,
                context is the context of execution of the Javascript code.
    '''
    errors = []
    jsCode = []
    unescapedBytes = []
    urlsFound = []
    
    try:
        code = unescapeHTMLEntities(code)
        scriptElements = re.findall(reJSscript, code, re.DOTALL | re.IGNORECASE)
        if scriptElements:
            code = ''
            for scriptElement in scriptElements:
                code += scriptElement + '\n\n'
        code = jsbeautifier.beautify(code)
        jsCode.append(code)
    
        if code is not None and JS_MODULE and not manualAnalysis:
            if context is None:
                context = PyV8.JSContext(Global())
            context.enter()
            # Hooking the eval function
            context.eval('eval=evalOverride')
            #context.eval(preDefinedCode)
            while True:
                originalCode = code
                try:
                    context.eval(code)
                    evalCode = context.eval('evalCode')
                    evalCode = jsbeautifier.beautify(evalCode)
                    if evalCode != '' and evalCode != code:
                        code = evalCode
                        jsCode.append(code)
                    else:
                        break
                except:
                    error = str(sys.exc_info()[1])
                    open('jserror.log', 'ab').write(error + newLine)
                    errors.append(error)
                    break
            
            if code != '':
                escapedVars = re.findall('(\w*?)\s*?=\s*?(unescape\((.*?)\))', code, re.DOTALL)
                for var in escapedVars:
                    bytes = var[2]
                    if bytes.find('+') != -1 or bytes.find('%') == -1:
                        varContent = getVarContent(code, bytes)
                        if len(varContent) > 150:
                            ret = unescape(varContent)
                            if ret[0] != -1:
                                bytes = ret[1]
                                urls = re.findall('https?://.*$', bytes, re.DOTALL)
                                if bytes not in unescapedBytes:
                                   unescapedBytes.append(bytes)
                                for url in urls:
                                   if url not in urlsFound:
                                       urlsFound.append(url)
                    else:
                        bytes = bytes[1:-1]
                        if len(bytes) > 150:
                            ret = unescape(bytes)
                            if ret[0] != -1:
                                bytes = ret[1]
                                urls = re.findall('https?://.*$', bytes, re.DOTALL)
                                if bytes not in unescapedBytes:
                                   unescapedBytes.append(bytes)
                                for url in urls:
                                   if url not in urlsFound:
                                       urlsFound.append(url)
    except:
        traceback.print_exc(file=open(errorsFile, 'a'))
        errors.append('Unexpected error in the JSAnalysis module!!')
    finally:
        for js in jsCode:
            if js is None or js == '':
                 jsCode.remove(js)
    return [jsCode, unescapedBytes, urlsFound, errors, context]


def getVarContent(jsCode, varContent):
    '''
        Given the Javascript code and the content of a variable this method tries to obtain the real value of the variable, cleaning expressions like "a = eval; a(js_code);"
        
        @param jsCode: The Javascript code (string)
        @param varContent: The content of the variable (string)
        @return: A string with real value of the variable
    '''
    clearBytes = ''
    varContent = varContent.replace('\n', '')
    varContent = varContent.replace('\r', '')
    varContent = varContent.replace('\t', '')
    varContent = varContent.replace(' ', '')
    parts = varContent.split('+')
    for part in parts:
        if re.match('["\'].*?["\']', part, re.DOTALL):
            clearBytes += part[1:-1]
        else:
            part = escapeString(part)
            varContent = re.findall(part + '\s*?=\s*?(.*?)[,;]', jsCode, re.DOTALL)
            if varContent:
                clearBytes += getVarContent(jsCode, varContent[0])
    return clearBytes


def isJavascript(content):
    '''
        Given an string this method looks for typical Javscript strings and try to identify if the string contains Javascrit code or not.
        
        @param content: A string
        @return: A boolean, True if it seems to contain Javascript code or False in the other case
    '''
    jsStrings = ['var ', ';', ')', '(', 'function ', '=', '{', '}', 'if(', 'if (', 'else{', 'else {','else if', 'return', 'while(', 'while (', 'for(', 'for (',
                 ',', 'eval']
    keyStrings = [';', '(', ')']
    stringsFound = []
    limit = 15
    #JS should at least contain ';', ')', '(', 'var', '='
    minDistinctStringsFound = 5
    minRatio = 10
    results = 0
    length = len(content)
    smallScriptLength = 100

    if re.findall(reJSscript, content, re.DOTALL | re.IGNORECASE):
        return True
    
    for char in content:
        if (ord(char) < 32 and char not in ['\n', '\r', '\t', '\f', '\x00']) or ord(char) >= 127:
            return False

    for string in jsStrings:
        cont = content.count(string)
        results += cont
        if cont > 0 and string not in stringsFound:
            stringsFound.append(string)
        elif cont == 0 and string in keyStrings:
            return False

    numDistinctStringsFound = len(stringsFound)
    ratio = (results*100.0)/length
    if (results > limit and numDistinctStringsFound >= minDistinctStringsFound) or \
            (length < smallScriptLength and ratio > minRatio):
        return True
    else:
        return False


def searchObfuscatedFunctions(jsCode, function):
    '''
        Search for obfuscated functions in the Javascript code
        
        @param jsCode: The Javascript code (string)
        @param function: The function name to look for (string)
        @return: List with obfuscated functions information [functionName,functionCall,containsReturns] 
    '''
    obfuscatedFunctionsInfo = []
    if jsCode != None:
        match = re.findall('\W('+function+'\s{0,5}?\((.*?)\)\s{0,5}?;)', jsCode, re.DOTALL)
        if match:
           for m in match:
              if re.findall('return', m[1], re.IGNORECASE):
                 obfuscatedFunctionsInfo.append([function, m, True])
              else:
                 obfuscatedFunctionsInfo.append([function, m, False])
        obfuscatedFunctions = re.findall('\s*?((\w*?)\s*?=\s*?'+function+')\s*?;', jsCode, re.DOTALL)
        for obfuscatedFunction in obfuscatedFunctions:
           obfuscatedElement = obfuscatedFunction[1]
           obfuscatedFunctionsInfo += searchObfuscatedFunctions(jsCode, obfuscatedElement)
    return obfuscatedFunctionsInfo


def unescape(escapedBytes, unicode = True):
    '''
        This method unescapes the given string
        
        @param escapedBytes: A string to unescape
        @return: A tuple (status,statusContent), where statusContent is an unescaped string in case status = 0 or an error in case status = -1
    '''
    #TODO: modify to accept a list of escaped strings?
    unescapedBytes = ''
    if unicode:
        unicodePadding = '\x00'
    else:
        unicodePadding = ''
    try:
        if escapedBytes.lower().find('%u') != -1 or escapedBytes.lower().find('\u') != -1 or escapedBytes.find('%') != -1:
            if escapedBytes.lower().find('\u') != -1:
                splitBytes = escapedBytes.split('\\')
            else:
                splitBytes = escapedBytes.split('%')
            for i in range(len(splitBytes)):
                splitByte = splitBytes[i]
                if splitByte == '':
                    continue
                if len(splitByte) > 4 and re.match('u[0-9a-f]{4}', splitByte[:5], re.IGNORECASE):
                    unescapedBytes += chr(int(splitByte[3]+splitByte[4], 16))+chr(int(splitByte[1]+splitByte[2],16))
                    if len(splitByte) > 5:
                        for j in range(5,len(splitByte)): 
                            unescapedBytes += splitByte[j] + unicodePadding
                elif len(splitByte) > 1 and re.match('[0-9a-f]{2}', splitByte[:2], re.IGNORECASE):
                    unescapedBytes += chr(int(splitByte[0]+splitByte[1], 16)) + unicodePadding
                    if len(splitByte) > 2:
                        for j in range(2,len(splitByte)): 
                            unescapedBytes += splitByte[j] + unicodePadding
                else:
                    if i != 0:
                        unescapedBytes += '%' + unicodePadding
                    for j in range(len(splitByte)):
                        unescapedBytes += splitByte[j] + unicodePadding
        else:
            unescapedBytes = escapedBytes
    except:
        return (-1, 'Error while unescaping the bytes')
    return (0, unescapedBytes)


if __name__ == "__main__":
    from PDFCore import *
    from JSAnalysis import *
    #create object pdf
    from PDFCore import *

    fileName="/home/thole/Documents/samples/pdf_samples/AAAA/sample3/ffe8db8803d5ead7a7c4d4dfd393e4601a91b867"
    pdfParser = PDFParser()
    ret, pdf = pdfParser.parse(fileName, True,True,False)
    infoObjects=pdf.getInfoObject()

    rawCode=pdf.getObject(1)
    code=rawCode.getJSCode()[0]
    if rawCode.getType() == "stream":
            rawCode=rawCode.getStream()
    else:
            rawCode=rawCode.getValue()

    print JSUnpack(code,rawCode,infoObjects)
