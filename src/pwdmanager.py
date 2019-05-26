'''
Della Porta Antonio - 18/06/2018

pwd-manager - A simple secrets file encryption tool
descr: questo e' lo script che va lanciato per utilizzare il tool

Digitare 'python pwdmanager.py --help' per ulteriori informazioni.

'''

import argparse
import pwdcrypto as pwdc
from os import urandom
from base64 import b64encode

def main():
    master_key = ''
    parser = argparse.ArgumentParser(prog='SFE', description='Simple secrets file encryption tool')
    parser.add_argument('-s', dest='secrets_file', help='Source secrets file (see README.txt)')
    parser.add_argument('-p', dest='dest_path', help='Specify a path for the output file')
    parser.add_argument('-e', action='store_true', default=False, dest='encrypt_m', help='Encrypt Mode (default mode)')
    parser.add_argument('-d', action='store_true', default=False, dest='decrypt_m', help='Decrypt Mode')
    parser.add_argument('-r', type=int, default=None, dest='key_len', help='Script choose a random key (you don\'t need to specify the -k argument) of length KEY_LEN')
    parser.add_argument('-k', dest='key', help='Specify the key')
    parser.add_argument('-sf', dest='s_filename', default='.pwd-manager', help='Specify the path where you want to save the file containing salt:hmac pairs (default is .pwd-manager). In decryption mode this is the file where you saved the salt:hmac pairs that is needed to decrypt and verify the secrets.')
    parser.add_argument('--no-delete', action='store_false', default=True, dest='no_delete', help='Do not delete the source file (valid for -d and -e mode)')
    parser.add_argument('--version', action='version', version='%(prog)s 0.1 alpha')

    results = parser.parse_args()

    if results.secrets_file is None:
        print 'You need to provide a secrets file through -s argument (see --help)'
        exit()

    if results.encrypt_m == results.decrypt_m:
        print 'You need to choice just one argument chosen between -e and -d (see --help)'
        exit()

    if results.key is None and results.key_len is None:
        print 'You need to choice a key (or you can use -r option for a random key)'
        exit()

    if results.key_len is not None:
        random_bytes = urandom(results.key_len)
        master_key = b64encode(random_bytes)
    else:
        if len(results.key) <= 8:
            x = raw_input('Key length is too short, you want to continue? (Y/n): ')
            if ord(x) == ord('N') or ord(x) == ord('n'):
                exit()
        master_key = results.key

    if results.encrypt_m:
        if results.dest_path is not None:
            pwdc.encrypt_secrets(master_key, results.secrets_file, results.dest_path, results.s_filename, results.no_delete)
        else:
            pwdc.encrypt_secrets(master_key, results.secrets_file, s_filename = results.s_filename, delete = results.no_delete)
          
        print 'Secrets succesfully encrypted!'
        print 'Key used: ' + master_key
          
        if results.dest_path is not None:
            print 'Encrypted secrets can be found in:' + results.dest_path + '. Backup this file in a secure place.'
        else:
            print 'Encrypted secrets can be found in: secret_file.txt. Backup this file in a secure place.'

        print '.pwd-manager file can now be found in the path where you are running this. Backup it.'

    else:
        if results.dest_path is not None:
            pwdc.decrypt_secrets(master_key, results.secrets_file, results.dest_path, results.s_filename, results.no_delete)
        else:
            pwdc.decrypt_secrets(master_key, results.secrets_file, s_filename = results.s_filename, delete = results.no_delete)

        print 'Secrets succesfully decrypted!'
        print 'Key used: ' + master_key
          
        if results.dest_path is not None:
            print 'Decrypted secrets can be found in:' + results.dest_path + '.'
        else:
            print 'Decrypted secrets can be found in: plaintext_file.txt. Encrypt it again when you\'re done using credentials.'


if __name__ == '__main__':
    main()
