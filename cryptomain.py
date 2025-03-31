from Crypto.Cipher import AES, Blowfish, DES3
from utility import *
from Advance import advance
from Simple import simple





def cryptomain(opt, m, dt, keysize, blocksize, kvalue, ivect):
	#print("Choose an operation:")
	#print("1. Encrypt")
	#print("2. Decrypt")
	operation = opt

	#if operation == "1" or operation == "2":
		#print("Choose encryption mode:")
		#print("1. Simple (Random Key & IV)")
		#print("2. Advanced (User-defined Key & IV)")
		encryption_mode = m
	#else:
		#return
	#print("Choose data type:")
	#print("1. Simple text")
	#print("2. File (txt, pdf, ppt, jpg, mp4)")
	type_of_data = dt


	algorithms = {"1": AES, "2": Blowfish, "3": DES3, "4": "Twofish"}
	#print("Choose an encryption algorithm:")
	#print("1. AES")
	#print("2. Blowfish")
	#print("3. 3DES")
	#print("4. Twofish")

	choice = alg
	#if choice not in algorithms:
		#print("Invalid choice.")
		#return

	algorithm = algorithms[choice]
	#if algorithm == AES:
	    #print("AES requires a key size of 16 bytes (AES-128), 24 bytes (AES-192), or 32 bytes (AES-256) and block size 16 bytes.")
	#elif algorithm == Blowfish:
	    #print("Blowfish requires a key size between 4 and 56 bytes and block size of 8 bytes.")
	#elif algorithm == DES3:
	    #print("3DES requires a key size of 16 bytes or 24 bytes and a block size of 8 bytes.")
	#elif algorithm == "Twofish":
	    #print("Twofish requires a key size of 16 bytes, 24 bytes or 32 bytes and a block size of 16 bytes.")
	key_size = keysize
	block_size = blocksize
	#if not validate_key_and_block_size(algorithm, key_size, block_size):
		#return


	if encryption_mode == "1" and operation=="1":
		key,iv= get_random_bytes(key_size), get_random_bytes(block_size)
	elif (encryption_mode == "2" and operation=="1")or (encryption_mode == "2" and operation=="2"):
		key = bytes.fromhex(kvalue).strip())
		iv = bytes.fromhex(ivect).strip())

		if len(key) != key_size or len(iv) != block_size:
			return 406
				#raise ValueError("Error: Incorrect key or IV length.")



	elif encryption_mode == "1" and operation=="2":

		key = bytes.fromhex(kvalue).strip())
		iv = 000000000000
		if len(key) != key_size :
			return 406
			#raise ValueError("Error: Incorrect key length.")




	#key, iv = get_user_key_iv(encryption_mode,operation, key_size, block_size)


































	#Start from here





	if encryption_mode=="1":
		if type_of_data == "1":
		
			if operation == "1":
				plaintext = iptext
				ciphertext =encrypt_text(algorithm, key, block_size, plaintext, iv)
				print(f"Encrypted text (hex): {ciphertext.hex()}")
				print(f"Key (hex): {key.hex()}")
				
			else:
				ciphertext_hex = iptext
				ciphertext = bytes.fromhex(ciphertext_hex)
				iv = ciphertext[:block_size]
				
				decrypted_text = decrypt_twofish(ciphertext[block_size:], key, iv).decode() if algorithm == "Twofish" else decrypt_text(algorithm, key, block_size, ciphertext,iv)
				print(f"Decrypted text: {decrypted_text}")
		else:
			if operation == "1":
				input_file = fname
				hex_file = "hex_" + input_file + ".txt" # Store hex file
				encrypted_file = "encrypted_crpty_" + input_file    # Encrypted file in given format
				last=input_file.rfind('.')
				encrypted_hex_file = "encrypted_hex_" + input_file[:last]+ ".txt" # Encrypted file in hex

				convert_to_text(input_file, hex_file)

				encrypt_file(algorithm, key,iv, block_size, hex_file, encrypted_file, encrypted_hex_file)
				print(f"Encrypted file stored in: {encrypted_file}")
				print(f"Encrypted hex stored in: {encrypted_hex_file}")
				print(f"Key (hex): {key.hex()}")
			else:
				input_file = fname
				decrypt_simple(algorithm, key, block_size, input_file)
	elif encryption_mode=="2":
		if type_of_data == "1":
        
			if operation == "1":
				plaintext = iptext
				ciphertext = encrypt_twofish(plaintext.encode(), key, iv) if algorithm == "Twofish" else encrypt_text(algorithm, key, block_size, plaintext, iv)
				print(f"Encrypted text (hex): {ciphertext.hex()}")
				print(f"Key (hex): {key.hex()}")
				print(f"IV (hex): {iv.hex()}")
			else:
				ciphertext_hex = iptext
				ciphertext = bytes.fromhex(ciphertext_hex)
				decrypted_text = decrypt_twofish(ciphertext, key, iv).decode() if algorithm == "Twofish" else decrypt_text(algorithm, key, block_size, ciphertext,iv)
				print(f"Decrypted text: {decrypted_text}")
		else:
			if operation == "1":
				input_file = fname
				hex_file = "hex_" + input_file + ".txt" # Store hex file
				encrypted_file = "encrypted_crpty_" + input_file    # Encrypted file in given format
				last=input_file.rfind('.')
				encrypted_hex_file = "encrypted_hex_" + input_file[:last]+ ".txt" # Encrypted file in hex
				convert_to_text(input_file, hex_file)

				encrypt_file(algorithm, key,iv, block_size, hex_file, encrypted_file, encrypted_hex_file)
				print(f"Encrypted file stored in: {encrypted_file}")
				print(f"Encrypted hex stored in: {encrypted_hex_file}")
				print(f"Key (hex): {key.hex()}")
				print(f"IV (hex): {iv.hex()}")
			else:
				input_file = fname
				decrypt_advanced(algorithm, key, iv, block_size, input_file)
	#else:
		#return
	return 0


































