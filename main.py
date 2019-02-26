from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Random import random
from Crypto import Random
from Crypto.PublicKey import RSA, DSA
from Crypto.Signature import DSS
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256, SHA512, SHA3_256
import time
import filecmp

#function for AES encryption
def encryption_AES(plaintext, key, mode):
	if("CBC" in mode):
		iv = Random.new().read(AES.block_size)
		cipher = AES.new(key, AES.MODE_CBC, iv)
		encrypted = cipher.encrypt(pad(plaintext, AES.block_size))
		return encrypted, iv
	elif("CTR" in mode):
		cipher = AES.new(key, AES.MODE_CTR)
		encrypted = cipher.encrypt(plaintext)
		return encrypted

#function for AES decryption
def decryption_AES(ciphertext, key, mode, iv=None):
	try:
		if("CBC" in mode):
			cipher = AES.new(key, AES.MODE_CBC, iv)
			ct_padded = cipher.decrypt(ciphertext)
			decrypted = unpad(ct_padded, AES.block_size)
		elif("CTR" in mode):
			cipher = AES.new(key, AES.MODE_CTR)
			decrypted = cipher.decrypt(ciphertext)
		return decrypted
	except ValueError, KeyError:
		print("Incorrect Decryption")

#function for SHA hashing
def hashing_SHA(file):
	start_time = time.time()
	hash_obj = SHA256.new(file)
	temp_time = (time.time()-start_time)*1000
	print("SHA256 Time: ", temp_time)
	print("SHA256 Time per Byte: ", temp_time/256)

	start_time = time.time()
	hash_obj = SHA512.new(file)
	temp_time = (time.time()-start_time)*1000
	print("SHA512 Time: ", temp_time)
	print("SHA512 Time per Byte: ", temp_time/512)

	start_time = time.time()
	hash_obj = SHA3_256.new(file)
	temp_time = (time.time()-start_time)*1000
	print("SHA3_256 Time: ", temp_time)
	print("SHA3_256 Time per Byte: ", temp_time/256)

#function for RSA encryption
def encryption_RSA(plaintext, publickey):
	encryptor = PKCS1_OAEP.new(publickey)
	encrypted = encryptor.encrypt(plaintext)
	return encrypted

#function for RSA decryption
def decryption_RSA(ciphertext, privatekey):
	decryptor = PKCS1_OAEP.new(privatekey)
	decrypted = decryptor.decrypt(ciphertext)
	return decrypted

#function for DSA signature
def signature_DSA(message, privatekey):
	hash_obj = SHA256.new(message)
	signer = DSS.new(privatekey, 'fips-186-3')
	signature = signer.sign(hash_obj)
	return signature

#function for DSA verification
def verification_DSA(message, publickey, signature):
	hash_obj = SHA256.new(message)
	verifier = DSS.new(publickey,'fips-186-3')
	try:
		verifier.verify(hash_obj, signature)
		print "Signature Verified"
	except ValueError:
		print "Incorrect Signature"

#function for correctness check
def correctness_check(plaintext, decrypted):
	#print (filecmp.cmp(plaintext, decrypted))
	if(filecmp.cmp(plaintext, decrypted)):
		print "Text Match!"
	else:
		print "Do not Match!"

##############################################################
##############################################################

filename_kb = "test_data_4kb.txt"
filename_mb = "test_data_1mb.txt"
KB_SIZE = 4000
MB_SIZE = 1000000

def AES_CBC_FUNC(filename, key_size):
	f = open(filename, 'rb')
	p = open('enc.txt', 'wb')
	data = f.read()

	print("AES-CBC")
	print(filename)
	print("Key Size: ", key_size)
	start_time = time.time()	
	key = get_random_bytes(key_size/8)
	print("Key Gen Time: ", (time.time()-start_time)*1000)

	start_time = time.time()
	enc_data, iv = encryption_AES(data, key, "CBC")
	temp_time = (time.time()-start_time)*1000
	print("Enc Time: ", temp_time)
	print("Enc Time per Byte: ", temp_time/(KB_SIZE if filename==filename_kb else MB_SIZE))
	p.write(enc_data)
	f.close()
	p.close()

	f = open('enc.txt', 'rb')
	p = open('dec.txt', 'wb')
	
	enc_data = f.read()
	start_time = time.time()
	dec_data = decryption_AES(enc_data, key, "CBC", iv=iv)
	temp_time = (time.time()-start_time)*1000
	print("Dec Time: ", temp_time)
	print("Dec Time per Byte: ", temp_time/(KB_SIZE if filename==filename_kb else MB_SIZE))
	p.write(dec_data)
	#correctness_check(filename, 'dec.txt')

def AES_CTR_FUNC(filename, key_size):
	f = open(filename, 'rb')
	data = f.read()
	f.close()

	print("AES-CTR")
	print(filename)
	print("Key Size: ", key_size)
	start_time = time.time()
	key = get_random_bytes(key_size/8)
	print("Key Gen Time: ", (time.time()-start_time)*1000)

	start_time = time.time()
	enc_data = encryption_AES(data, key, "CTR")
	temp_time = (time.time()-start_time)*1000
	print("Enc Time: ", temp_time)
	print("Enc Time per Byte: ", temp_time/(KB_SIZE if filename==filename_kb else MB_SIZE))
	start_time = time.time()
	dec_data = decryption_AES(enc_data, key, "CTR")
	temp_time = (time.time()-start_time)*1000
	print("Dec Time: ", temp_time)
	print("Dec Time per Byte: ", temp_time/(KB_SIZE if filename==filename_kb else MB_SIZE))

def HASH_FUNC(filename):
	print("HASH")
	print(filename)
	f = open(filename, 'rb')
   	data = f.read()
   	f.close()
	hashing_SHA(data)

def RSA_FUNC(filename, key_size):
	f = open(filename, 'rb')
	p = open('enc.txt', 'wb')

	print("RSA")
	print(filename)
	print("Key Size: ", key_size)
	random_generator = Random.new().read
	start_time = time.time()
	privatekey = RSA.generate(key_size, random_generator)
	publickey = privatekey.publickey()
	print("Key Gen Time: ", (time.time()-start_time)*1000)

	temp_time = 0.0
	while True:
		data = f.read(key_size/8 - 42)
		if not data:
			break
		start_time = time.time()
		enc_data = encryption_RSA(data, publickey)
		temp_time += time.time()-start_time
		p.write(enc_data)
	f.close()
	p.close()
	temp_time *= 1000
	print("Enc Time: ", temp_time)
	print("Enc Time per Byte: ", temp_time/(KB_SIZE if filename==filename_kb else MB_SIZE))

	f = open('enc.txt', 'rb')
	p = open('dec.txt', 'wb')
	temp_time = 0.0
	while True:
		data = f.read(key_size/8)
		if not data:
			break
		start_time = time.time()
		dec_data = decryption_RSA(data, privatekey)
		temp_time += time.time()-start_time
		p.write(dec_data)
	p.close()
	f.close()
	temp_time *= 1000
	print("Dec Time: ", temp_time)
	print("Dec Time per Byte: ", temp_time/(KB_SIZE if filename==filename_kb else MB_SIZE))

def DSA_FUNC(filename, key_size):
	f = open(filename, 'rb')
	data = f.read()
	f.close()
	print("DSA")
	print(filename)
	print("Key Size: ", key_size)

	start_time = time.time()
	privatekey = DSA.generate(key_size)
	publickey = privatekey.publickey()
	print("Key Gen Time: ", (time.time()-start_time)*1000)
	start_time = time.time()
	signature = signature_DSA(data, privatekey)
	temp_time = (time.time()-start_time)*1000
	print("Sig Prod Time: ", temp_time)
	print("Sig Prod Time per Byte: ", temp_time/(KB_SIZE if filename==filename_kb else MB_SIZE))
	start_time = time.time()
	verification_DSA(data, publickey, signature)
	temp_time = (time.time()-start_time)*1000
	print("Sig Veri Time: ", temp_time)
	print("Sig Veri Time per Byte: ", temp_time/(KB_SIZE if filename==filename_kb else MB_SIZE))

##############################################################
##############################################################

#(a) 128-bit AES key, encrypt and decrypt using AES in the CBC mode
AES_CBC_FUNC(filename_kb, 128)
AES_CBC_FUNC(filename_mb, 128)

#(b) 128-bit AES key, encrypt and decrypt using AES in the CTR mode
AES_CTR_FUNC(filename_kb, 128)
AES_CTR_FUNC(filename_mb, 128)

#(c)
AES_CTR_FUNC(filename_kb, 256)
AES_CTR_FUNC(filename_mb, 256)

#(d)
HASH_FUNC(filename_kb)
HASH_FUNC(filename_mb)

#(e)
RSA_FUNC(filename_kb, 2048)
RSA_FUNC(filename_mb, 2048)

#(f)
RSA_FUNC(filename_kb, 3072)
RSA_FUNC(filename_mb, 3072)

#(g)
DSA_FUNC(filename_kb, 2048)
DSA_FUNC(filename_mb, 2048)

#(h)
DSA_FUNC(filename_kb, 3072)
DSA_FUNC(filename_mb, 3072)














