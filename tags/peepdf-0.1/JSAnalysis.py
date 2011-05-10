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
    JSAnalysis.py
    This module contains some functions to analyse Javascript code inside the PDF file
'''

import sys,re,os
try:
	from spidermonkey import Runtime
	JS_MODULE = True 
except:
	JS_MODULE = False
newLine = os.linesep         
                    
def analyseJS(code):
    '''
        Search for obfuscated functions in the Javascript code
        @param code The Javascript code (string)
        @return List with analysis information of the Javascript code: [JSCode,unescapedBytes,urlsFound], where JSCode is a list with the several stages Javascript code, unescapedBytes is a list with the parameters of unescape functions, and urlsFound is a list with the URLs found in the unescaped bytes. 
    '''
    error = ''
    errors = []
    JSCode = []
    unescapedBytes = []
    urlsFound = []
    oldStdErr = sys.stderr
    errorFile = open('jserror.log','w')
    sys.stderr = errorFile
		
    if code != None and JS_MODULE:
        r = Runtime()
        context = r.new_context()
        while True:
            evalFunctionsData = searchObfuscatedFunctions(code, 'eval')
            originalElement = code
            for evalFunctionData in evalFunctionsData:
                if not evalFunctionData[2]:
                    modifiedCode = evalFunctionData[1][0].replace(evalFunctionData[0],'return')
                    code = originalElement.replace(evalFunctionData[1][0],modifiedCode)
                else:
                    code = originalElement.replace(evalFunctionData[1][0],evalFunctionData[1][1]+';')
                try:
                    executedJS = context.eval_script(code)
                    if executedJS == None:
                        raise exception
                    break
                except:                   
                    if evalFunctionData[2]:
                        modifiedCode = evalFunctionData[1][0].replace(evalFunctionData[0],'return')
                        code = originalElement.replace(evalFunctionData[1][0],modifiedCode)
                    else:
                        code = originalElement.replace(evalFunctionData[1][0],evalFunctionData[1][1]+';')
                    try:
                        executedJS = context.eval_script(code)
                        if executedJS == None:
                            raise exception
                    except:
                        code = originalElement
                        continue
            else:
                break
            if executedJS != originalElement and executedJS != None and executedJS != '':
                code = executedJS
                JSCode.append(code)                
            else:                                            
                break
        
        if code != None:
            escapedVars = re.findall('(\w*?)\s*?=\s*?(unescape\((.*?)\))', code, re.DOTALL)
            for var in escapedVars:
                bytes = var[2]
                if bytes.find('+') != -1:
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
    errorFile.close()
    sys.stderr = oldStdErr
    errorFileContent = open('jserror.log','r').read()
    if errorFileContent != '' and errorFileContent.find('JavaScript error') != -1:
        lines = errorFileContent.split(newLine)
        for line in lines:
            if line.find('JavaScript error') != -1 and line not in errors:
                errors.append(line)
    return [JSCode,unescapedBytes,urlsFound,errors]
       
def getVarContent(jsCode, varContent):
    '''
		Given the Javascript code and the content of a variable this method try to obtain the real value of the variable, cleaning expressions like "a = eval; a(js_code);"
		@param jsCode The Javascript code (string)
		@param varContent The content of the variable (string)
		@return An string with real value of the variable
	'''
    clearBytes = ''
    varContent = varContent.replace('\n','')
    varContent = varContent.replace('\r','')
    varContent = varContent.replace('\t','')
    varContent = varContent.replace(' ','')
    parts = varContent.split('+')
    for part in parts:
        if re.match('["\'].*?["\']', part, re.DOTALL):
            clearBytes += part[1:-1]
        else:
            varContent = re.findall(part + '\s*?=\s*?(.*?)[,;]', jsCode, re.DOTALL)
            if varContent != []:
                clearBytes += getVarContent(jsCode, varContent[0])
    return clearBytes

def isJavascript(content):
    '''
        Given an string this method looks for typical Javscript strings and try to identify if the string contains Javascrit code or not.
        @param content (string)
        @return A boolean, True if it seems to contain Javascript code or False in the other case
    '''
    JSStrings = ['var ',';',')','(','function ','=','{','}','if ','else','return','while ','for ',',','eval']
    keyStrings = [';','(',')']
    stringsFound = []
    limit = 15
    minDistinctStringsFound = 5
    results = 0
    
    for char in content:
        if (ord(char) < 32 and char not in ['\n','\r','\t','\f','\x00'])  or ord(char) >= 127:
            return False

    for string in JSStrings:
        cont = content.count(string)
        results += cont
        if cont > 0 and string not in stringsFound:
            stringsFound.append(string)
        elif cont == 0 and string in keyStrings:
            return False

    if results > limit and len(stringsFound) >= minDistinctStringsFound:
        return True
    else:
        return False
    
def searchObfuscatedFunctions(jsCode, function):
    '''
		Search for obfuscated functions in the Javascript code
		@param jsCode The Javascript code (string)
		@param function The function name to look for (string)
		@return List with obfuscated functions information [functionName,functionCall,containsReturns] 
	'''
    obfuscatedFunctionsInfo = []
    if jsCode != None:
	    match = re.findall('\W('+function+'\s{0,5}?\((.*?)\)\s{0,5}?;)', jsCode, re.DOTALL)
	    if match != []:
	       for m in match:
	          if re.findall('return',m[1],re.IGNORECASE) != []:
	             obfuscatedFunctionsInfo.append([function,m,True])
	          else:
	             obfuscatedFunctionsInfo.append([function,m,False])
	    obfuscatedFunctions = re.findall('\s*?((\w*?)\s*?=\s*?'+function+')\s*?;', jsCode, re.DOTALL)
	    for obfuscatedFunction in obfuscatedFunctions:
	       obfuscatedElement = obfuscatedFunction[1]
	       obfuscatedFunctionsInfo += searchObfuscatedFunctions(jsCode, obfuscatedElement)
    return obfuscatedFunctionsInfo

def unescape(escapedBytes):
    '''
        This method unescape the given string with Javascript escaped chars
        @param escapedBytes (string)
        @return A tuple (status,statusContent), where statusContent is an unescaped string in case status = 0 or an error in case status = -1
    '''
    #TODO: modify to accept a list of espaced strings?
    unescapedBytes = ''
    try:
        if escapedBytes.find('%u') != -1 or escapedBytes.find('%U') != -1:
            for i in range(2,len(escapedBytes)-1,6):
                unescapedBytes += chr(int(escapedBytes[i+2]+escapedBytes[i+3],16))+chr(int(escapedBytes[i]+escapedBytes[i+1],16))
        elif escapedBytes.find('%') != -1:
            for i in range(1,len(escapedBytes)-1,3):
                unescapedBytes += chr(int(escapedBytes[i]+escapedBytes[i+1],16))
        elif re.match('[0-9a-f]{2,*}',escapedBytes,re.IGNORECASE):
            for i in range(1,len(escapedBytes)-1,2):
                unescapedBytes += chr(int(escapedBytes[i]+escapedBytes[i+1],16))
    except:
        return (-1,'Error while unescaping the bytes')
    return (0,unescapedBytes)