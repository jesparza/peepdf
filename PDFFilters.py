# Some code has been reused and modified from the original by Mathieu Fenniak:
# Parameters management in Flate and LZW algorithms, asciiHexDecode and ascii85Decode
#
# Copyright (c) 2006, Mathieu Fenniak
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
# * Redistributions of source code must retain the above copyright notice,
# this list of conditions and the following disclaimer.
# * Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
# * The name of the author may not be used to endorse or promote products
# derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

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
	PDFFilters.py
	Module to manage encoding/decoding in PDF files
'''

import sys, zlib, lzw


def decodeStream(stream, filter, parameters = {}):
	'''
		Decode the given stream
		@param stream Stream to be decoded (string)
		@param filter Filter to apply to decode the stream
		@param parameters List of PDFObjects containing the parameters for the filter
		@return A tuple (status,statusContent), where statusContent is the decoded stream in case status = 0 or an error in case status = -1
	'''
	if filter == '/ASCIIHexDecode' or filter == 'AHx':
		ret = asciiHexDecode(stream)
	elif filter == '/ASCII85Decode' or filter == 'A85':
		ret = ascii85Decode(stream)
	elif filter == '/LZWDecode' or filter == 'LZW':
		ret = lzwDecode(stream, parameters)
	elif filter == '/FlateDecode' or filter == 'Fl':
		ret = flateDecode(stream, parameters)
	elif filter == '/RunLengthDecode' or filter == 'RL':
		ret = runLengthDecode(stream)
	elif filter == '/CCITTFaxDecode' or filter == 'CCF':
		ret = ccittFaxDecode(stream, parameters)
	elif filter == '/JBIG2Decode':
		ret = jbig2Decode(stream, parameters)
	elif filter == '/DCTDecode' or filter == 'DCT':
		ret = dctDecode(stream, parameters)
	elif filter == '/JPXDecode':
		ret = jpxDecode(stream)
	elif filter == '/Crypt':
		ret = crypt(stream, parameters) 
	return ret

def encodeStream(stream, filter, parameters = {}):
	'''
		Encode the given stream
		@param stream Stream to be decoded (string)
		@param filter Filter to apply to decode the stream
		@param parameters List of PDFObjects containing the parameters for the filter
		@return A tuple (status,statusContent), where statusContent is the encoded stream in case status = 0 or an error in case status = -1
	'''
	if filter == '/ASCIIHexDecode':
		ret = asciiHexEncode(stream)
	elif filter == '/ASCII85Decode':
		ret = ascii85Encode(stream)
	elif filter == '/LZWDecode':
		ret = lzwEncode(stream, parameters)
	elif filter == '/FlateDecode':
		ret = flateEncode(stream, parameters)
	elif filter == '/RunLengthDecode':
		ret = runLengthEncode(stream)
	elif filter == '/CCITTFaxDecode':
		ret = ccittFaxEncode(stream, parameters)
	elif filter == '/JBIG2Decode':
		ret = jbig2Encode(stream, parameters)
	elif filter == '/DCTDecode':
		ret = dctEncode(stream, parameters)
	elif filter == '/JPXDecode':
		ret = jpxEncode(stream)
	elif filter == '/Crypt':
		ret = crypt(stream, parameters)
	return ret

def ascii85Decode(stream):
	decodedStream = ''
	group = []
	x = 0
	hitEod = False
	# remove all whitespace from data
	try:
		data = [y for y in stream if not (y in ' \n\r\t')]
		while not hitEod and x < len(data):
		    c = data[x]
		    if len(decodedStream) == 0 and c == '<' and data[x+1] == '~':
		        x += 2
		        continue
		    #elif c.isspace():
		    #    x += 1
		    #    continue
		    elif c == 'z':
		        assert len(group) == 0
		        decodedStream += '\x00\x00\x00\x00'
		        continue
		    elif c == "~" and data[x+1] == '>':
		        if len(group) != 0:
		            # cannot have a final group of just 1 char
		            cnt = len(group) - 1
		            group += [ 85, 85, 85 ]
		            hitEod = cnt
		        else:
		            break
		    else:
		        c = ord(c) - 33
		        group += [ c ]
		    if len(group) >= 5:
		        b = group[0] * (85**4) + \
		            group[1] * (85**3) + \
		            group[2] * (85**2) + \
		            group[3] * 85 + \
		            group[4]
		        c4 = chr((b >> 0) % 256)
		        c3 = chr((b >> 8) % 256)
		        c2 = chr((b >> 16) % 256)
		        c1 = chr(b >> 24)
		        decodedStream += (c1 + c2 + c3 + c4)
		        if hitEod:
		            decodedStream = decodedStream[:-4+hitEod]
		        group = []
		    x += 1
	except:
	    return (-1,'Unspecified error')
	return (0,decodedStream)

def ascii85Encode(stream):
	encodedStream = ''
	return (-1,'Warning: Ascii85Encode not supported yet')

def asciiHexDecode(stream):
	eod = '>'
	decodedStream = ''
	char = ''
	index = 0
	while index < len(stream):
		c = stream[index]
		if c == eod:
			if decodedStream % 2 != 0:
				char += '0'
				try:
					decodedStream += chr(int(char, base=16))
				except:
					return (-1,'Error in hexadecimal conversion')
			break
		elif c.isspace():
			index += 1
			continue
		char += c
		if len(char) == 2:
			try:
				decodedStream += chr(int(char, base=16))
			except:
				return (-1,'Error in hexadecimal conversion')
			char = ''
		index += 1
	return (0,decodedStream)

def asciiHexEncode(stream):
	try:
		encodedStream = stream.encode('hex')	
	except:
		return (-1,'Error in hexadecimal conversion')
	return (0,encodedStream)

def flateDecode(stream, parameters):
	decodedStream = ''
	try:
		decodedStream = zlib.decompress(stream)
	except:
		return (-1,'Error decompressing string')

	if parameters == None or parameters == {}:
		return (0,decodedStream)
	else:
		if parameters.has_key('/Predictor'):
			predictor = parameters['/Predictor'].getRawValue()
		else:
			predictor = None
		# Columns = num samples per row
		if parameters.has_key('/Columns'):
			columns = parameters['/Columns'].getRawValue()
		else:
			columns = None
		# Colors = num components per sample
		if parameters.has_key('/Colors'):
			colors = parameters['/Colors'].getRawValue()
		else:
			colors = None
		if parameters.has_key('/BitsPerComponent'):
			bits = parameters['/BitsPerComponent'].getRawValue()
		else:
			bits = None
		if predictor != None and predictor != 1:
			# PNG prediction:
			if predictor >= 10 and predictor <= 15:
				output = ''
				# PNG prediction can vary from row to row
				rowlength = columns + 1
				prev_rowdata = (0,) * rowlength
				for row in xrange(len(decodedStream) / rowlength):
					rowdata = [ord(x) for x in decodedStream[(row*rowlength):((row+1)*rowlength)]]
					filterByte = rowdata[0]
					if filterByte == 0:
						pass
					elif filterByte == 1:
						for i in range(2, rowlength):
							rowdata[i] = (rowdata[i] + rowdata[i-1]) % 256
					elif filterByte == 2:
						for i in range(1, rowlength):
							rowdata[i] = (rowdata[i] + prev_rowdata[i]) % 256
					else:
						# unsupported PNG filter
						#sys.exit("Unsupported PNG filter %r" % filterByte)
						return (-1,'Unsupported parameters')
					prev_rowdata = rowdata
					output += (''.join([chr(x) for x in rowdata[1:]]))
				return (0,output)
			else:
				# unsupported predictor
				#sys.exit("Unsupported flatedecode predictor %r" % predictor)
				return (-1,'Unsupported parameters')
		else:
			return (0,decodedStream)		

def flateEncode(stream, parameters):
	encodedStream = ''
	if parameters == None or parameters == {}:
		try:
			return (0,zlib.compress(stream))
		except:
			return (-1,'Error compressing string')
	else:
		if parameters.has_key('/Predictor'):
			predictor = parameters['/Predictor'].getRawValue()
		else:
			predictor = None
		if parameters.has_key('/Columns'):
			columns = parameters['/Columns'].getRawValue()
		else:
			columns = None
		if parameters.has_key('/Colors'):
			colors = parameters['/Colors'].getRawValue()
		else:
			colors = None
		if parameters.has_key('/BitsPerComponent'):
			bits = parameters['/BitsPerComponent'].getRawValue()
		else:
			bits = None
		if predictor != None and predictor != 1:
			# PNG prediction:
			if predictor >= 10 and predictor <= 15:
				output = ''
				# PNG prediction can vary from row to row
				for row in xrange(len(stream) / columns):
					rowdata = [ord(x) for x in stream[(row*columns):((row+1)*columns)]]
					filterByte = predictor - 10
					rowdata = [filterByte]+rowdata
					if filterByte == 0:
						pass
					elif filterByte == 1:
						for i in range(len(rowdata)-1,1,-1):
							if rowdata[i] < rowdata[i-1]:
								rowdata[i] = rowdata[i] + 256 - rowdata[i-1]
							else:
								rowdata[i] = rowdata[i] - rowdata[i-1]
					elif filterByte == 2:
						pass
					else:
						return (-1,'Unsupported parameters')
					output += (''.join([chr(x) for x in rowdata]))
			else:
				# unsupported predictor
				#sys.exit("Unsupported flatedecode predictor %r" % predictor)
				return (-1,'Unsupported parameters')
		else:
			output = stream
		try:
			return (0,zlib.compress(output))
		except:
			return (-1,'Error compressing string')

def lzwDecode(stream, parameters):
	decodedStream = ''
	try:
		generator = lzw.decompress(stream)
		for c in generator:
			decodedStream += c
	except:
		return (-1,'Error decompressing string')
	
	if parameters == None or parameters == {}:
		return (0,decodedStream)
	else:
		if parameters.has_key('/Predictor'):
			predictor = parameters['/Predictor'].getRawValue()
		else:
			predictor = None
		if parameters.has_key('/Columns'):
			columns = parameters['/Columns'].getRawValue()
		else:
			columns = None
		if parameters.has_key('/Colors'):
			colors = parameters['/Colors'].getRawValue()
		else:
			colors = None
		if parameters.has_key('/BitsPerComponent'):
			bits = parameters['/BitsPerComponent'].getRawValue()
		else:
			bits = None
		if parameters.has_key('/EarlyChange'):
			earlyChange = parameters['/EarlyChange'].getRawValue()
		else:
			earlyChange = None
		if predictor != None and predictor != 1:
			# PNG prediction:
			if predictor >= 10 and predictor <= 15:
				output = ''
				# PNG prediction can vary from row to row
				rowlength = columns + 1
				prev_rowdata = (0,) * rowlength
				for row in xrange(len(decodedStream) / rowlength):
					rowdata = [ord(x) for x in decodedStream[(row*rowlength):((row+1)*rowlength)]]
					filterByte = rowdata[0]
					if filterByte == 0:
						pass
					elif filterByte == 1:
						for i in range(2, rowlength):
							rowdata[i] = (rowdata[i] + rowdata[i-1]) % 256
					elif filterByte == 2:
						for i in range(1, rowlength):
							rowdata[i] = (rowdata[i] + prev_rowdata[i]) % 256
					else:
						# unsupported PNG filter
						#sys.exit("Unsupported PNG filter %r" % filterByte)
						return (-1,'Unsupported parameters')
					prev_rowdata = rowdata
					output += (''.join([chr(x) for x in rowdata[1:]]))
				return (0,output)
			else:
				# unsupported predictor
				#sys.exit("Unsupported flatedecode predictor %r" % predictor)
				return (-1,'Unsupported parameters')

def lzwEncode(stream, parameters):
	encodedStream = ''
	if parameters == None or parameters == {}:
		try:
			generator = lzw.compress(stream)
			for c in generator:
				encodedStream += c
			return (0,encodedStream)
		except:
			return (-1,'Error compressing string')
	else:
		if parameters.has_key('/Predictor'):
			predictor = parameters['/Predictor'].getRawValue()
		else:
			predictor = None
		if parameters.has_key('/Columns'):
			columns = parameters['/Columns'].getRawValue()
		else:
			columns = None
		if parameters.has_key('/Colors'):
			colors = parameters['/Colors'].getRawValue()
		else:
			colors = None
		if parameters.has_key('/BitsPerComponent'):
			bits = parameters['/BitsPerComponent'].getRawValue()
		else:
			bits = None
		if predictor != None and predictor != 1:
			# PNG prediction:
			if predictor >= 10 and predictor <= 15:
				output = ''
				# PNG prediction can vary from row to row
				for row in xrange(len(stream) / columns):
					rowdata = [ord(x) for x in stream[(row*columns):((row+1)*columns)]]
					filterByte = predictor - 10
					rowdata = [filterByte]+rowdata
					if filterByte == 0:
						pass
					elif filterByte == 1:
						for i in range(len(rowdata)-1,1,-1):
							if rowdata[i] < rowdata[i-1]:
								rowdata[i] = rowdata[i] + 256 - rowdata[i-1]
							else:
								rowdata[i] = rowdata[i] - rowdata[i-1]
					elif filterByte == 2:
						pass
					else:
						return (-1,'Unsupported parameters')
					output += (''.join([chr(x) for x in rowdata]))
			else:
				# unsupported predictor
				#sys.exit("Unsupported flatedecode predictor %r" % predictor)
				return (-1,'Unsupported parameters')
		else:
			output = stream
		try:
			generator = lzw.compress(output)
			for c in generator:
				encodedStream += c
			return (0,encodedStream)
		except:
			return (-1,'Error decompressing string')

def runLengthDecode(stream):
	decodedStream = ''
	index = 0
	try:
		while index < len(stream):
			length = ord(stream[index]) 
			if length >= 0 and length < 128:
				decodedStream += stream[index+1:index+length+2]
				index += length+2
			elif length > 128 and length < 256:
				decodedStream += stream[index+1] * (257 - length)
				index += 2
			else:
				break
	except:
		return (-1,'Error decoding string')
	return (0,decodedStream)

def runLengthEncode(stream):
	encodedStream = ''
	return (-1,'Warning: RunLengthEncode not supported yet')

def ccittFaxDecode(stream, parameters):
	decodedStream = ''
	return (-1,'Warning: CcittFaxDecode not supported yet')

def ccittFaxEncode(stream, parameters):
	encodedStream = ''
	return (-1,'Warning: CcittFaxEncode not supported yet')

def crypt(stream, parameters):
	decodedStream = ''
	return (-1,'Warning: Crypt not supported yet')

def decrypt(stream, parameters):
	encodedStream = ''
	return (-1,'Warning: Decrypt not supported yet')

def dctDecode(stream, parameters):
	decodedStream = ''
	return (-1,'Warning: DctDecode not supported yet')

def dctEncode(stream, parameters):
	encodedStream = ''
	return (-1,'Warning: DctEncode not supported yet')

def jbig2Decode(stream, parameters):
	decodedStream = ''
	return (-1,'Warning: Jbig2Decode not supported yet')

def jbig2Encode(stream, parameters):
	encodedStream = ''
	return (-1,'Warning: Jbig2Encode not supported yet')

def jpxDecode(stream):
	decodedStream = ''
	return (-1,'Warning: JpxDecode not supported yet')

def jpxEncode(stream):
	encodedStream = ''
	return (-1,'Warning: JpxEncode not supported yet')