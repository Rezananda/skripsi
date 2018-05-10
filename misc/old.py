import jwt

SECRET = 'whatsup'

def generate_token():
    data = {
        'user' = 'tuti',
        'admin' = True
    }
    return jwt.encode(data, SECRET)

def validate_token(token):
    try :
        return jwt.decode(token, SECRET)
    except Exception as error :
        return false

def main():
    token = generate_token()
    is_valid = validate_token(token)
    print('Token is valid', is_valid)

main()