# Noctoz Steam Account Switcher using steam.guard by ValvePython and PyAutoIt by jacexh #

import autoit, time, os, json, subprocess, base64, hashlib, binascii
from base64 import b64encode, b64decode
import steam.guard as sa
from Crypto.Cipher import AES

# Config settings here, feel free to change them!
configpath = os.getenv('APPDATA')+"\\NoctozAccountSwitcher"
configFile = "dummy.txt" # This is set to a real value when logging in

key = bytearray(16) # This will be set based on password

data = {}

# Config
if not os.path.exists(configpath):
    os.makedirs(configpath)

# Defining key stuff #

def cls():
    os.system('cls' if os.name=='nt' else 'clear')
	
def enter():
	input("Press ENTER to continue . . .")

def validateInput(input):
	if input.isdigit() == False or int(input) >= i or int(input) < 1:
		return False
	else:
		return True

# This is used to hash the password used to login to the application
def hashAppPassword(password):
    # Hash a password for storing.
    salt = hashlib.sha256(os.urandom(60)).hexdigest().encode('ascii')
    pwdhash = hashlib.pbkdf2_hmac('sha512', password.encode('utf-8'), salt, 100000)
    pwdhash = binascii.hexlify(pwdhash)
    return (salt + pwdhash).decode('ascii')
 
# This verifies the application password
def verifyAppPassword(storedPassword, providedPassword):
    # Verify a stored password against one provided by user
    salt = storedPassword[:64]
    storedPassword = storedPassword[64:]
    pwdhash = hashlib.pbkdf2_hmac('sha512', 
                                  providedPassword.encode('utf-8'), 
                                  salt.encode('ascii'), 
                                  100000)
    pwdhash = binascii.hexlify(pwdhash).decode('ascii')
    return pwdhash == storedPassword

def encryptPassword(password):
	cipher = AES.new(key, AES.MODE_EAX)
	#print(password.encode())
	ciphertext, tag = cipher.encrypt_and_digest(password.encode())
	#print(ciphertext)
	#print(b64encode(ciphertext))
	#print(b64encode(ciphertext).decode())
	return b64encode(ciphertext).decode(), b64encode(cipher.nonce).decode(), b64encode(tag).decode()

def decryptPassword(accountData):
	nonce = accountData['nonce']
	cipher = AES.new(key, AES.MODE_EAX, b64decode(nonce))
	encryptedPassword = accountData['password']
	#print(encryptedPassword)
	#print(b64decode(encryptedPassword))
	tag = accountData['tag']
	password = cipher.decrypt_and_verify(b64decode(encryptedPassword), b64decode(tag))
	#print(password)
	#print(password.decode())
	return password.decode()
	
def createNewAccount():
	newusername = input("Enter the username: ")
	newpassword = input("Enter the password: ")
	newmobile = input("Enter the mobile code, blank if none: ")

	password, nonce, tag = encryptPassword(newpassword)

	data['accounts'].append({  
		'username': newusername,
		'password': password,
		'mobile': newmobile,
		'nonce': nonce,
		'tag': tag
	})
	
	with open(configFile, 'w') as outfile:  
		json.dump(data, outfile, sort_keys = False, indent = 4, ensure_ascii=False)
	
	print("Account created.")
	enter()
	authenticatedMain()

	
def deleteAccount(i):
	chosenDelete = input("Type the number for the account you would like to delete: ")
	
	while validateInput(chosenDelete) == False: #validation, check if its a number
		print("ERROR: Choose an account on the list.")
		chosenDelete = input("Type the number for the account you would like to delete: ")
		
	chosenDelete = int(chosenDelete) - 1 #line it up with the json, make it an int
	del data['accounts'][chosenDelete]
	
	with open(configFile, 'w') as outfile:  
		json.dump(data, outfile, sort_keys = False, indent = 4, ensure_ascii=False)
	
	print("Account deleted.")
	enter()
	authenticatedMain()

	
def editConfig():
	subprocess.call(['notepad.exe', configFile]) #we use subprocess here because its better and it works
	enter()
	authenticatedMain()

def moveAccount(i):
	chosenMove = input("Type the number for the account you would like to move: ")

	while validateInput(chosenMove) == False: #validation, check if its a number
		print("ERROR: Choose an account on the list.")
		chosenMove = input("Type the number for the account you would like to move: ")

	chosenMove = int(chosenMove) - 1 #line it up with the json, make it an int

	chosenPosition = input("Type the position you want to move the account to: ")

	while validateInput(chosenPosition) == False: #validation, check if its a number
		print("ERROR: Choose a valid position.")
		chosenPosition = input("Type the position you want to move the account to: ")

	chosenPosition = int(chosenPosition) - 1 #line it up with the json, make it an int

	itemToMove = data['accounts'].pop(chosenMove)
	data['accounts'].insert(chosenPosition, itemToMove)

	with open(configFile, 'w') as outfile:  
		json.dump(data, outfile, sort_keys = False, indent = 4, ensure_ascii=False)
	
	print("Account moved to top.")
	enter()
	authenticatedMain()

def browserLogin(i):
	chosenAccount = input("Type the number for the account you would like to display login details for: ")
	
	while validateInput(chosenAccount) == False: #validation, check if its a number
		print("ERROR: Choose an account on the list")
		chosenAccount = input("Type the number for the account you would like to display login details for: ")

	chosenAccount = int(chosenAccount) - 1 #line it up with json, make int

	password = decryptPassword(data['accounts'][chosenAccount])
	
	print("username: {}".format(data['accounts'][chosenAccount]['username']))
	print("password: {}".format(password))
	if data['accounts'][chosenAccount]['mobile']:
		print("2FA code: {}".format(sa.generate_twofactor_code(base64.b64decode(data['accounts'][chosenAccount]['mobile']))))
	enter()
	authenticatedMain()
	
def mobileCode(i):
	chosenAccount = input("Type the number for the account you would like to display login details for: ")
	
	while validateInput(chosenAccount) == False: #validation, check if its a number
		print("ERROR: Choose an account on the list")
		chosenAccount = input("Type the number for the account you would like to display login details for: ")

	chosenAccount = int(chosenAccount) - 1 #line it up with json, make int
	if data['accounts'][chosenAccount]['mobile']:
		print("2FA code: {}".format(sa.generate_twofactor_code(base64.b64decode(data['accounts'][chosenAccount]['mobile']))))
	else:
		print("Error finding mobile code for account")
	enter()
	authenticatedMain()

def main():
	userName = input("Input username: ")
	global configFile # Reference the global configFile
	configFile = configpath + "\\" + userName + ".json"
	
	# Check if the files exists
	# If it does not exist we create it and add some initial data
	if not os.path.exists(configFile):
		# Request user to choose a password
		password = input("Choose password: ")
		hashedPassword = hashAppPassword(password)
		initialData = { "password": hashedPassword, "accounts": [] }
		with open (configFile, "w+") as dataFile:
			json.dump(initialData, dataFile, sort_keys = False, indent = 4, ensure_ascii=False)

	# When we get here we always have a file with some data
	with open(configFile, 'r') as dataFile:
		try:
			global data # Need to access the global instance
			data = json.load(dataFile)
		except json.decoder.JSONDecodeError as error:
			print("Failed to decode json data. File is corrupt.")
			return

	# Check password
	password = input("Input password: ")
	while not verifyAppPassword(data["password"], password):
		print("Incorrect password entered!")
		password = input("Input password: ")

	global key # Reference the global key variable
	stringKey = password.ljust(16, 'x') # We need to make sure the string is at least 16 long so we add padding
	stringKey = stringKey[:16] # In case the string is longer we trim it
	key = stringKey.encode()
	
	authenticatedMain()

# This is what you enter once you are authenticated
def authenticatedMain():
	cls()
	
	print("########################")
	print("# Noctoz Steam Account Switcher #")
	print("########################")
	print("")
	
	global i
	i = 1
	for account in data['accounts']:
		print(str(i) + ' - ' + account['username'])
		i = i + 1

	print("")
	print("n - Add new account")
	print("d - Delete an account")
	print("m - Move account to index")
	print("e - Edit config")
	print("b - Print login details (for browser logins)")
	print("c - Mobile code only")
	print("q - Quit")
	print("")
	print("Typing in the account and ENTER will auto login to that account")

	chosenAccount = input("Type your choice then press ENTER: ")


	while chosenAccount.isdigit() == False: # validation, check if its a number, this check is needed to differentiate the character options from numerical and also to provide some nice feedback to the user
		if chosenAccount == "n" or chosenAccount == "e" or chosenAccount == "d" or chosenAccount == "m" or chosenAccount == "b" or chosenAccount == "c" or chosenAccount == "q": # we skip if its one of the alpha values
			break
		print("ERROR: Please enter a valid option")
		chosenAccount = input("Type your choice then press ENTER: ")


	if chosenAccount.isdigit() == False: #if its still false its one of the alpha values
		if chosenAccount == "n":
			createNewAccount()		
		
		if chosenAccount == "d":
			deleteAccount(i)

		if chosenAccount == "m":
			moveAccount(i)
			
		if chosenAccount == "e":
			editConfig()
			
		if chosenAccount == "b":
			browserLogin(i)
			
		if chosenAccount == "c":
			mobileCode(i)
			
		if chosenAccount == "q":
			exit()

	else: #they chose a number of some sorts

		while validateInput(chosenAccount) == False: #validation, check if the account exists
			print("ERROR: Choose an account on the list.")
			chosenAccount = input("Type the number for the account then press ENTER: ")

		chosenAccount = int(chosenAccount) - 1
		
		print("Killing Steam...")
		os.system('taskkill /f /im steam.exe') #kill steam
		print("Waiting 3 seconds before starting Steam...")
		time.sleep(3)

		# For some reason subprocess doesn't work, leaving this commented out until I figure out why...
		#dargds = ['C:\Program Files (x86)\Steam\Steam.exe', '-login', data['accounts'][chosenAccount]['username'], data['accounts'][chosenAccount]['password']]#args
		#subprocess.call(dargds) #run steam

		password = decryptPassword(data['accounts'][chosenAccount])

		print("Launching Steam...")
		os.system('start "" "C:\Program Files (x86)\Steam\Steam.exe" -login {} {}'.format(data['accounts'][chosenAccount]['username'], password))

		if data['accounts'][chosenAccount]['mobile']: #if theres a mobile code
			print("Waiting for Steamguard window...")
			autoit.win_wait("Steam Guard") #wait for window... sometimes it takes a while

			print("Steamguard window found, generating code...")
			code = sa.generate_twofactor_code(base64.b64decode(data['accounts'][chosenAccount]['mobile']))
			
			autoit.win_activate("Steam Guard") #open it up in case it's not activated
			autoit.win_wait_active("Steam Guard") #wait for it to be activated, in case of delay
			print("Entering auth code: {} into window...".format(code))
			autoit.send(code)
			time.sleep(0.2) #small delay cant hurt
			autoit.send('{ENTER}')
		
		input()
		authenticatedMain()

if __name__ == "__main__":
	main()
