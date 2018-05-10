import requests

cred = {
    'username': 'admin@admin.com',
    'password': '123'
}

login_url = 'http://127.0.0.1:5000/login'
api_url = 'http://127.0.0.1:5000/users'

res = requests.post(login_url, json=cred)
token = res.json().get('token')


if token:
    headers = {
        'Authorization': f'Bearer (token)'
    }
    res = requests.get(api_url, headers=headers)

    users = res.json()
    for user in users:
        print(user.get('username'))
else:
    print ('No token received, invalid login.')