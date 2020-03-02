import requests

import constants
import utils


def get_aac_token(email, password):
    token_param = 'Token'
    enc_password = utils.encrypt_password(email, password)
    print(enc_password)
    params = {'Email': email,
              'EncryptedPasswd': enc_password,
              'add_account': '1',
              'accountType': 'HOSTED_OR_GOOGLE',
              'google_play_services_version': '11951438',
              'has_permission': '1', 'source': 'android',
              'device_country': 'in',
              'lang': 'in',
              'client_sig': '38918a453d07199354f8b19af05ec6562ced5788',
              'callerSig': '38918a453d07199354f8b19af05ec6562ced5788', 'service': 'sj',
              'callerPkg': 'com.google.android.gms'}

    raw_response = requests.post(constants.AUTH_URL, data=params)

    if raw_response.status_code >= 400:
        print(raw_response.text.split())

    if raw_response.status_code == 200:
        response = raw_response.text.split()
        for param in response:
            if param.startswith(token_param):
                print(email, param[6:])
                return email, param[6:]
    else:
        return None, None


file_handler = open("credentials.txt", "r")
cred_handler = open("token.txt", "w")
for line in file_handler:
    credential = line.split(sep=' ')
    email, token = get_aac_token(credential[0], credential[1])
    if email is not None and token is not None:
        cred_handler.write(email + ' ' + token + "\n")

cred_handler.close()
file_handler.close()
