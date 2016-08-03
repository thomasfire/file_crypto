#!/usr/bin/python3
# -*- coding: utf-8 -*-

#this is lib for easy using Twofish encryption
""" Developer and Author: Thomas Fire https://github.com/thomasfire (Telegram: @Thomas_Fire)
### Main manager: Uliy Bee
"""

from twofish import Twofish
from hashlib import sha512, sha256, md5
from codecs import decode
from sys import argv
from getpass import getpass
from os import urandom
from skein import threefish, skein1024

#returns secure hash
'''
smstr is string you wanna to take hash
mode twofish for generating 256-bit hash, or threefish to generate 1024-bit hash and tweak
'''
def gethash(smstr, mode='twofish'):
	#generating salt
	salt=b'gierghyuihflfugirugh89GYOB  IIUH ^%^&& YHGVF!@#$**R F MV GV^I"OLp;of\e\3 t49hrhf h hrushg vb'
	nhash=skein1024(salt+smstr.encode('ascii')).digest()
	tweak=salt+smstr.encode('ascii')

	# generating key 2^18 times
	if mode=='twofish':
		for x in range(2**18):
			nhash=sha512(salt+nhash).digest()
		return sha256(salt+nhash).digest()

	elif mode=='threefish':
		for x in range(2**18):
			nhash=skein1024(nhash).digest()
			if not x%256:
				tweak=md5(tweak+salt).digest()
		return skein1024(salt+nhash).digest(), tweak

#encrypts file via password
def fencrypt(filen, password, tweak=0, mode='twofish'):
	f=open(filen,'r')
	smstr=f.read()
	f.close()
	if mode=='twofish':
		# splitting it to blocks with 16-bytes len
		if len(smstr)%16:
			nstr=str(smstr+'%'*(16-len(smstr)%16)).encode('utf-8')
		else:
			nstr=smstr.encode('utf-8')

		psswd=Twofish(password)
		encredstr=b'' # ENCRyptED STRing

		# encrypting blocks
		for x in range(int(len(nstr)/16)):
			encredstr+=psswd.encrypt(nstr[x*16:(x+1)*16])

	elif mode=='threefish':
		# splitting it to blocks with 128-bytes len
		if len(smstr)%128:
			nstr=str(smstr+'%'*(128 - len(smstr)%128)).encode('utf-8')
		else:
			nstr=smstr.encode('utf-8')

		psswd=threefish(password,tweak)
		encredstr=b'' # ENCRyptED STRing

		# encrypting blocks
		for x in range(int(len(nstr)/128)):
			encredstr+=psswd.encrypt_block(nstr[x*128:(x+1)*128])
	# writing it to file
	f=open(filen,'wb')
	f.write(encredstr)
	f.close()

#decrypts file via password,returns decrypted text
def fdecrypt(filen, password, tweak=0, mode='twofish'):
	# reading file in byte mode
	f=open(filen,'rb')
	smstr=f.read()
	f.close()

	if mode=='twofish':
		psswd=Twofish(password)
		decredstr=b''

		# decrypting blocks
		for x in range(int(len(smstr)/16)):
			decredstr+=psswd.decrypt(smstr[x*16:(x+1)*16])

	elif mode=='threefish':

		psswd=threefish(password,tweak)
		decredstr=b''

		# decrypting blocks
		for x in range(int(len(smstr)/128)):
			decredstr+=psswd.decrypt_block(smstr[x*128:(x+1)*128])

	return decode(decredstr,'utf-8').strip('%')



def main():
	if len(argv)>2 and (argv[1]=='-e2' or argv[1]=='--encrypt2'):
		vari=False
		while not vari: # checking if it is needed password
			inone=getpass('Password to encrypt files: ')
			intwo=getpass('Re-enter : ')
			if inone==intwo:
				password=gethash(inone, mode='twofish')
				vari=True
			else:
				print('Wrong validation,retry\n')

		fencrypt(argv[2], password)
		print('Successful encryption')


	elif len(argv)>2 and (argv[1]=='-e3' or argv[1]=='--encrypt3' or argv[1]=='--encrypt' or argv[1]=='-e'):
		vari=False
		while not vari: # checking if it is needed password
			inone=getpass('Password to encrypt files: ')
			intwo=getpass('Re-enter : ')
			if inone==intwo:
				password, tweak=gethash(inone, mode='threefish')
				vari=True
			else:
				print('Wrong validation,retry\n')

		fencrypt(argv[2], password, tweak, mode='threefish')
		print('Successful encryption')

	elif len(argv)>2 and (argv[1]=='-d2' or argv[1] =='--decrypt2'):      
		while True:
			try:
				password = gethash(getpass(), mode='twofish')
				print(fdecrypt(argv[2], password))
				break
			except KeyboardInterrupt:
				print('')
				exit()
			except Exception as e:
				print('Smth went wrong, try again ', e)

	elif len(argv)>2 and (argv[1]=='-d3' or argv[1] =='--decrypt3' or argv[1]=='--decrypt' or argv[1]=='-d'):      
		while True:
			try:
				password, tweak = gethash(getpass(), mode='threefish')
				print(fdecrypt(argv[2], password, tweak, mode='threefish'))
				break
			except KeyboardInterrupt:
				print('')
				exit()
			except:
				print('Smth went wrong, try again')

	else:
		print('Usage: python3 fcrypto.py -setup')



if __name__ == '__main__':
	main()
