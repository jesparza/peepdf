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
	PDFCrypto.py
	
	Module to manage cryptographuc operations with PDF files
'''	

import hashlib,struct,random,warnings
warnings.filterwarnings("ignore")


def computeEncryptionKey(password, ownerPass, fileID, pElement, keyLength = 128, revision = 3):
	'''
		Compute an encryption key to encrypt/decrypt the PDF file
		@param password The password entered by the user
		@param ownerPass The computed owner password
		@param fileID The /ID element in the trailer dictionary of the PDF file
		@param pElement The /P element of the Encryption dictionary
		@param keyLength The lenght of the key
		@param revision The algorithm revision
		@return The computed encryption key in string format
	'''
	paddingString = '\x28\xBF\x4E\x5E\x4E\x75\x8A\x41\x64\x00\x4E\x56\xFF\xFA\x01\x08\x2E\x2E\x00\xB6\xD0\x68\x3E\x80\x2F\x0C\xA9\xFE\x64\x53\x69\x7A'
	keyLength = keyLength/8
	lenPass = len(password)
	if lenPass > 32:
		password = password[:32]
	elif lenPass < 32:
		password += paddingString[:32-lenPass]
	md5input = password + ownerPass + struct.pack('<I',int(pElement)) + fileID
	if revision > 3:
		md5input += '\xFF'*4
	key = hashlib.md5(md5input).digest()
	if revision > 2:
		counter = 0
		while counter < 50:
			key = hashlib.md5(key[:keyLength]).digest()
			counter += 1
	return key

def computeObjectKey(id, generationNum, encryptionKey, keyLengthBytes):
	'''
		Compute the key necessary to encrypt each object, depending on the id and generation number
		@param id The object id
		@param generationNum The generation number of the object
		@param encryptionKey The encryption key
		@param keyLengthBytes The length of the encryption key in bytes
		@return The computed key in string format
	'''	
	key = encryptionKey + struct.pack('<I',id)[:3] + struct.pack('<I',generationNum)[:2]
	# AES: key += '\x73\x41\x6C\x54'
	key = hashlib.md5(key).digest()
	if keyLengthBytes+5 < 16:
		key = key[:keyLengthBytes+5]
	# AES: block size = 16 bytes, initialization vector (16 bytes), random, first bytes encrypted string
	return key

def computeOwnerPass(ownerPassString, userPassString, keyLength = 128, revision = 3):
	'''
		Compute the owner password necessary to compute the encryption key of the PDF file
		@param ownerPassString The owner password entered by the user
		@param userPassString The user password entered by the user
		@param keyLength The lenght of the key
		@param revision The algorithm revision
		@return The computed password in string format
	'''	
	paddingString = '\x28\xBF\x4E\x5E\x4E\x75\x8A\x41\x64\x00\x4E\x56\xFF\xFA\x01\x08\x2E\x2E\x00\xB6\xD0\x68\x3E\x80\x2F\x0C\xA9\xFE\x64\x53\x69\x7A'
	keyLength = keyLength/8
	lenPass = len(ownerPassString)
	if lenPass > 32:
		ownerPassString = ownerPassString[:32]
	elif lenPass < 32:
		ownerPassString += paddingString[:32-lenPass]
	rc4Key = hashlib.md5(ownerPassString).digest()
	if revision > 2:
		counter = 0
		while counter < 50:
			rc4Key = hashlib.md5(rc4Key).digest()
			counter += 1
	rc4Key = rc4Key[:keyLength]
	lenPass = len(userPassString)
	if lenPass > 32:
		userPassString = userPassString[:32]
	elif lenPass < 32:
		userPassString += paddingString[:32-lenPass]
	ownerPass = RC4(userPassString,rc4Key)
	if revision > 2:
		counter = 1
		while counter <= 19:
			newKey = ''
			for i in range(len(rc4Key)):
				newKey += chr(ord(rc4Key[i]) ^ counter)
			ownerPass = RC4(ownerPass,newKey)
			counter += 1
	return ownerPass

def computeUserPass(userPassString, ownerPass, fileID, pElement, keyLength = 128, revision = 3):
	'''
		Compute the user password of the PDF file
		@param userPassString The user password entered by the user
		@param ownerPass The computed owner password
		@param fileID The /ID element in the trailer dictionary of the PDF file
		@param pElement The /P element of the Encryption dictionary
		@param keyLength The lenght of the key
		@param revision The algorithm revision
		@return The computed password in string format
	'''
	userPass = ''
	paddingString = '\x28\xBF\x4E\x5E\x4E\x75\x8A\x41\x64\x00\x4E\x56\xFF\xFA\x01\x08\x2E\x2E\x00\xB6\xD0\x68\x3E\x80\x2F\x0C\xA9\xFE\x64\x53\x69\x7A'
	rc4Key = computeEncryptionKey(userPassString, ownerPass, fileID, pElement, keyLength, revision)
	if revision == 2:
		userPass = RC4(paddingString,rc4Key)
	elif revision > 2:
		counter = 1
		md5Input = paddingString + fileID
		hashResult = hashlib.md5(md5Input).digest()
		userPass = RC4(hashResult,rc4Key)	
		while counter <= 19:
			newKey = ''
			for i in range(len(rc4Key)):
				newKey += chr(ord(rc4Key[i]) ^ counter)
			userPass = RC4(userPass,newKey)
			counter += 1
	counter = 0
	while counter < 16:
		userPass += chr(random.randint(32,255))
		counter += 1
	return userPass

def RC4(data, key):
	'''
		RC4 implementation
		@param data Bytes to be encrypyed/decrypted
		@param key Key used for the algorithm
		@return The encrypted/decrypted bytes
	'''	
	y = 0
	hash = {}
	box = {}
	ret = ''
	keyLength  = len(key)
	dataLength = len(data)
	  
	#Initialization
	for x in range(256):
		hash[x] = ord(key[x % keyLength])
		box[x]	= x  
	for x in range(256):
		y			= (y + int(box[x]) + int(hash[x])) % 256 
		tmp		= box[x]
		box[x] = box[y]
		box[y] = tmp 

	z = y = 0
	for x in range(0,dataLength):
		z = (z + 1) % 256 
		y = (y + box[z]) % 256
		tmp    = box[z]
		box[z] = box[y]
		box[y] = tmp
		k	= box[((box[z] + box[y]) % 256)]
		ret	+= chr(ord(data[x]) ^ k)
	return ret