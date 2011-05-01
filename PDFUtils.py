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
    PDFUtils.py
    Module with some misc functions
'''

import os,re

def clearScreen():
	'''
		Simple method to clear the screen depending on the OS
	'''
	if os.name == 'nt':
		os.system('cls')
	elif os.name == 'posix':
		os.system('reset')
	elif os.name == 'mac':
		os.system('clear')

def countArrayElements(array):
    '''
        Simple method to count the repetitions of elements in an array
		@param array (list)
		@return A tuple (elements,counters), where elements is a list with the distinct elements and counters is the list with the number of times they appear in the array
		'''
    elements = []
    counters = []
    for element in array:
        if element in elements:
            indx = elements.index(element)
            counters[indx] += 1
        else:
            elements.append(element)
            counters.append(1)
    return elements,counters

def countNonPrintableChars(string):
    '''
        Simple method to return the non printable characters found in an string
		@param string
		@return Number of non printable characters in the string
	'''
    counter = 0
    for i in range(len(string)):
        if ord(string[i]) <= 31 or ord(string[i]) > 127:
            counter += 1
    return counter

def decodeName(name):
	'''
        Decode the given PDF name
		@param name (string)
		@return A tuple (status,statusContent), where statusContent is the decoded PDF name in case status = 0 or an error in case status = -1
	'''
	decodedName = name
	hexNumbers = re.findall('#([0-9a-f]{2})', name, re.DOTALL | re.IGNORECASE)
	for hexNumber in hexNumbers:
		try:
			decodedName = decodedName.replace('#'+hexNumber,chr(int(hexNumber,16)))
		except:
			return (-1,'Error decoding name')
	return (0,decodedName)

def decodeString(string):
	'''
        Decode the given PDF string
		@param string
		@return A tuple (status,statusContent), where statusContent is the decoded PDF string in case status = 0 or an error in case status = -1
	'''
	decodedString = string
	octalNumbers = re.findall('\\\\([0-7]{1-3})', decodedString, re.DOTALL)
	for octal in octalNumbers:
		try:
			decodedString = decodedString.replace('\\\\'+octal,chr(int(octal,8)))
		except:
			return (-1,'Error decoding string')
	return (0,decodedString)

def encodeName(name):
	'''
        Encode the given PDF name
		@param name (string)
		@return A tuple (status,statusContent), where statusContent is the encoded PDF name in case status = 0 or an error in case status = -1
	'''
	encodedName = ''
	if name[0] == '/':
		name = name[1:]
	for char in name:
		if char == '\0':
			encodedName += char
		else:
			try:
				hex = '%x' % ord(char)
				encodedName += '#'+hex
			except:
				return (-1,'Error encoding name')
	return (0,'/'+encodedName)

def encodeString(string):
	'''
        Encode the given PDF string
		@param string
		@return A tuple (status,statusContent), where statusContent is the encoded PDF string in case status = 0 or an error in case status = -1
	'''
	encodedString = ''
	try:
		for char in string:
			octal = '%o' % ord(char)
			encodedString += '\\'+(3-len(octal))*'0'+octal
	except:
		return (-1,'Error encoding string')
	return (0,encodedString)

def escapeRegExpString(string):
    '''
        Escape the given string to include it as a reg expression
        @param string
        @return Escaped string
    '''
    toEscapeChars = ['\\','(',')','.','|','^','$','*','+','?','[',']']
    escapedValue = ''
    for i in range(len(string)):
        if string[i] in toEscapeChars:
            escapedValue += '\\'+string[i]
        else:
            escapedValue += string[i]
    return escapedValue
    
def escapeString(string):
	'''
        Escape the given string
		@param string
		@return Escaped string
	'''
	toEscapeChars = ['\\','(',')']
	escapedValue = ''
	for i in range(len(string)):
		if string[i] in toEscapeChars and (i == 0 or string[i-1] != '\\'):
			if string[i] == '\\':
				if len(string) > i+1 and re.match('[0-7]',string[i+1]):
					escapedValue += string[i]
				else:
					escapedValue += '\\'+string[i]
			else:
				escapedValue += '\\'+string[i]
		elif string[i] == '\r':
			escapedValue += '\\r'
		elif string[i] == '\n':
			escapedValue += '\\n'
		elif string[i] == '\t':
			escapedValue += '\\t'
		elif string[i] == '\b':
			escapedValue += '\\b'
		elif string[i] == '\f':
			escapedValue += '\\f'
		else:
			escapedValue += string[i]
	return escapedValue

def getBytesFromFile(filename, offset, numBytes):
    '''
        Returns the num of bytes specified from a file, starting from the offset specified
		@param filename
		@param offset
		@param numBytes
		@return A tuple (status,statusContent), where statusContent is the bytes read in case status = 0 or an error in case status = -1
	'''
    if not isinstance(offset,int) or not isinstance(numBytes,int):
        return (-1,'The offset and the number of bytes mus be integers')
    if os.path.exists(filename):
        fileSize = os.path.getsize(filename)
        bytesFile = open(filename,'r')
        bytesFile.seek(offset)
        if offset+numBytes > fileSize:
            bytes = bytesFile.read()
        else:
            bytes = bytesFile.read(numBytes)
        bytesFile.close()
        return (0,bytes)
    else:
        return (-1,'File does not exist')

def hexToString(hexString):
	'''
		Simple method to convert an hexadecimal string to ascii string
		@param hexString
		@return A tuple (status,statusContent), where statusContent is an ascii string in case status = 0 or an error in case status = -1
	'''
	string = ''
	if len(hexString) % 2 != 0:
		hexString = '0'+hexString
	try:
		for i in range(0,len(hexString),2):
			string += chr(int(hexString[i]+hexString[i+1],16))
	except:
		return (-1,'Error in hexadecimal conversion')
	return (0,string)

def numToHex(num, numBytes):
    '''
        Given a number returns its hexadecimal format with the specified length, adding '\0' if necessary
		@param num Number (int)
		@param numBytes Length of the output (int)
		@return A tuple (status,statusContent), where statusContent is a number in hexadecimal format in case status = 0 or an error in case status = -1
	'''
    hexString = ''
    if not isinstance(num,int):
    	return (-1,'Bad number')
    try:
	    hexNumber = hex(num)[2:]
	    if len(hexNumber) % 2 != 0:
	        hexNumber = '0'+hexNumber
	    for i in range(0,len(hexNumber)-1,2):
	        hexString += chr(int(hexNumber[i]+hexNumber[i+1],16))
	    hexString = '\0'*(numBytes-len(hexString))+hexString
    except:
		return (-1,'Error in hexadecimal conversion')
    return (0,hexString)
                  		
def numToString(num, numDigits):
	'''
        Given a number returns its string format with the specified length, adding '0' if necessary
		@param num Number (int)
		@param numDigits Length of the string output (int)
		@return A tuple (status,statusContent), where statusContent is a number in string format in case status = 0 or an error in case status = -1
	'''
	if not isinstance(num,int):
		return (-1,'Bad number')
	strNum = str(num)
	if numDigits < len(strNum):
		return (-1,'Bad digit number')
	for i in range(numDigits-len(strNum)):
		strNum = '0' + strNum
	return (0,strNum)
     
def unescapeString(string):
	'''
        Unescape the given string
		@param string
		@return Unescaped string
	'''
	toUnescapeChars = ['\\','(',')']
	unescapedValue = ''
	i = 0
	while i < len(string):
		if string[i] == '\\' and i != len(string)-1:
			if string[i+1] in toUnescapeChars:
				if string[i+1] == '\\':
					unescapedValue += '\\'
					i += 1
				else:
					pass
			elif string[i+1] == 'r':
				i += 1
				unescapedValue += '\r'
			elif string[i+1] == 'n':
				i += 1
				unescapedValue += '\n'
			elif string[i+1] == 't':
				i += 1
				unescapedValue += '\t'
			elif string[i+1] == 'b':
				i += 1
				unescapedValue += '\b'
			elif string[i+1] == 'f':
				i += 1
				unescapedValue += '\f'
			else:
				unescapedValue += string[i]
		else:
			unescapedValue += string[i]
		i += 1
	return unescapedValue