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
	if input.isdigit() == False or int(input) >= accountCount or int(input) < 1:
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

# Encrypt steam account password
def encryptPassword(password):
	cipher = AES.new(key, AES.MODE_EAX)
	#print(password.encode())
	ciphertext, tag = cipher.encrypt_and_digest(password.encode())
	#print(ciphertext)
	#print(b64encode(ciphertext))
	#print(b64encode(ciphertext).decode())
	return b64encode(ciphertext).decode(), b64encode(cipher.nonce).decode(), b64encode(tag).decode()

# Decrypt steam account password
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

def validateNewUsername(newUsername):
	for account in data['accounts']:
		if account['username'] == newUsername:
			return False

	return True
	
def createNewAccount():
	newUsername = input("Enter the username: ")
	while validateNewUsername(newUsername) == False:
		print("ERROR: Choosen username not valid!")
		newUsername = input("Enter the username: ")
	newPassword = input("Enter the password: ")
	newNickname = input("Enter the nickname, black if none: ")

	password, nonce, tag = encryptPassword(newPassword)

	data['accounts'].append({  
		'username': newUsername,
		'password': password,
		'nickname': newNickname,
		'nonce': nonce,
		'tag': tag
	})
	
	with open(configFile, 'w') as outfile:  
		json.dump(data, outfile, sort_keys = False, indent = 4, ensure_ascii=False)
	
	print("Account created.")
	enter()
	authenticatedMain()
	
def deleteAccount():
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

def moveAccount():
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
	
	print("Account moved to new index.")
	enter()
	authenticatedMain()

def setNickname():
	chosenAccount = input("Type the number for the account you want to set nickname for: ")

	while validateInput(chosenAccount) == False: #validation, check if its a number
		print("ERROR: Choose an account on the list.")
		chosenAccount = input("Type the number for the account you want to set nickname for: ")

	chosenAccount = int(chosenAccount) - 1 #line it up with the json, make it an int

	newNickname = input("Type the new nickname: ")

	data['accounts'][chosenAccount]['nickname'] = newNickname

	with open(configFile, 'w') as outfile:  
		json.dump(data, outfile, sort_keys = False, indent = 4, ensure_ascii=False)

	print("Nickname set for account.")
	enter()
	authenticatedMain()

def printLoginDetails():
	chosenAccount = input("Type the number for the account you would like to display login details for: ")
	
	while validateInput(chosenAccount) == False: #validation, check if its a number
		print("ERROR: Choose an account on the list")
		chosenAccount = input("Type the number for the account you would like to display login details for: ")

	chosenAccount = int(chosenAccount) - 1 #line it up with json, make int

	password = decryptPassword(data['accounts'][chosenAccount])
	
	print("username: {}".format(data['accounts'][chosenAccount]['username']))
	print("password: {}".format(password))

	enter()
	authenticatedMain()

def printHeader():
	print("#################################")
	print("# Noctoz Steam Account Switcher #")
	print("#################################")
	print("")

# Valida and update data file
def validateDataFile():
	wasUpdated = False

	for account in data['accounts']:
		if not 'nickname' in account:
			print("No nickname field for account " + account['username'] + ", fixing!")
			account['nickname'] = ""
			wasUpdated = True

	# If data was updated we need to write to file
	if wasUpdated:
		with open(configFile, 'w') as outfile:  
			json.dump(data, outfile, sort_keys = False, indent = 4, ensure_ascii=False)
		
		print("Data file was updated")
		enter()

def main():
	cls()

	printHeader()
	print("You need to login to use this application!")
	userName = input("username: ")
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
	password = input("password: ")
	while not verifyAppPassword(data["password"], password):
		print("Incorrect password entered!")
		password = input("password: ")

	global key # Reference the global key variable
	stringKey = password.ljust(16, 'x') # We need to make sure the string is at least 16 long so we add padding
	stringKey = stringKey[:16] # In case the string is longer we trim it
	key = stringKey.encode()

	# Check if data file needs to be upgraded
	validateDataFile()
	
	authenticatedMain()

# This is what you enter once you are authenticated
def authenticatedMain():
	cls()
	
	printHeader()
	
	# List all registered account and count the number of accounts for input validation
	global accountCount
	accountCount = 1
	for account in data['accounts']:
		nicknameString = ""
		if account['nickname'] != "": # Do not print nickname if not set
			nicknameString = " ({})".format(account['nickname'])
		print(str(accountCount) + ' - ' + account['username'] + nicknameString)
		accountCount = accountCount + 1

	options = {}
	options['n'] = { 'description': "Add new account", 'func': createNewAccount }
	options['d'] = { 'description': "Delete an account", 'func': deleteAccount }
	options['m'] = { 'description': "Move account to index", 'func': moveAccount }
	options['s'] = { 'description': "Set nickname for account", 'func': setNickname }
	options['p'] = { 'description': "Print login details", 'func': printLoginDetails }
	options['q'] = { 'description': "Quit", 'func': exit }

	print("")
	for key in options:
		print(key + " - " + options[key]['description'])
	print("")
	print("Typing in the account and ENTER will auto login to that account")

	chosenAccount = input("Type your choice then press ENTER: ")

	# Check that the user has either choosen a number or a valid option
	while chosenAccount.isdigit() == False:
		if chosenAccount in options:
			break
		print("ERROR: Please enter a valid option")
		chosenAccount = input("Type your choice then press ENTER: ")

	# If the user did not choose a number we find the correct function for the choosen option
	if chosenAccount.isdigit() == False:
		options[chosenAccount]['func']()

	else: # If a number was choosen we attempt to login to that account
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
		
		input()
		authenticatedMain()

if __name__ == "__main__":
	main()
