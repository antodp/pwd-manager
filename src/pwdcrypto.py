'''
Della Porta Antonio - 18/06/2018

pwdcrypto.py - -
descr: in questo modulo sono contenute le funzioni principali di pwd-manager

'''


import hmac_5
import vigenere as vig
from os import urandom, chmod, remove
from base64 import b64encode

def find_between(s, first = '<', last = '>'):
    # cerca la sottostringa s contenuta tra i due caratteri first, last

    try:
        start = s.index(first) + len(first)
        end = s.index(last, start)
        return s[start:end]
    except ValueError:
        return ""

def generate_salt(num_bytes = 8):
    # generazione di num_bytes byte random utilizzando la funzione urandom
    # i byte vengono poi convertiti in un oggetto <str> con la funzione
    # b64encode 

     random_bytes = urandom(num_bytes)
     return b64encode(random_bytes) 

def build_sline(key, secret, salt):
    # questo metodo costruisce una entrata del file .pwd-manager in questo modo:
    # salt:hmac_sign

    hmac = hmac_5.hmac_sign(key, secret)
    ret = ''.join(s for s in [salt + ':', hmac + '\n'])
    return ret

def decrypt(key, cipher, shline):
    # metodo per decifrare il testo cipher
    # data la sua entrata salt:hmac e la chiave key

    salt = shline[0:12]
    hmac = shline[13:].rstrip()
    r_key = vig.vigenere_enc(key, salt)
    plaintext = vig.vigenere_dec(cipher, r_key)
    if hmac_5.hmac_verify(r_key, plaintext, hmac):
        return plaintext
    else:
        return ''

def encrypt(key, plaintext):
    # metodo per cifrare il testo plaintext
    # data la chiave e il testo stesso
    # il metodo ritorna una tupla del tipo:
    # 
    # (testo_cifrato, stringa salt:hmac)

    salt = generate_salt()
    r_key = vig.vigenere_enc(key, salt)
    secret_line = build_sline(r_key, plaintext, salt)
    return vig.vigenere_enc(plaintext, r_key), secret_line


def encrypt_secrets(key, input_filename, output_filename = 'secret_file.txt', s_filename = '.pwd-manager', delete = True):
    # metodo che gestisce la cifratura dei campi contenuti in input_filename
    # e scrive i risultati della cifratura in output_filename.
    # 
    # il metodo si occupa di eliminare il file input_filename di default. 
    # (se delete = False il file non verra' eliminato)

    with open(input_filename) as secrets:
        output = open(output_filename, 'w+')
        s_file = open(s_filename, 'w+')
        line = secrets.readline()
        while line:
            line = line.lstrip(' ')
            if not line.startswith('##: '):
                output.write(line)
            else:
                to_encrypt = find_between(line)
                encrypted, secret_line = encrypt(key, to_encrypt)
                line = line.replace(to_encrypt, encrypted)
                output.write(line)
                s_file.write(secret_line)
            line = secrets.readline()
        chmod('.pwd-manager', 384)
        output.close()
        s_file.close()
        if delete:
            try:
                remove(input_filename)
            except OSError, e:
                print "Error: %s - %s." % (e.filename, e.strerror)

def decrypt_secrets(key, input_filename, output_filename = 'plaintext_file.txt', s_filename = '.pwd-manager', delete = True):
    # metodo che gestisce la decifratura dei campi cifrati contenuti in input_filename
    # e scrive i risultati della decifratura in output_filename.
    # 
    # il metodo si occupa di eliminare il file input_filename di default. 
    # (se delete = False il file non verra' eliminato)


    with open(input_filename) as secrets:
        output = open(output_filename, 'w+')
        s_file = open(s_filename, 'r')
        line = secrets.readline()
        while(line):
            line = line.lstrip(' ')
            if not line.startswith('##: '):
                output.write(line)
            else:
                to_decrypt = find_between(line)
                s_line = s_file.readline()
                plaintext = decrypt(key, to_decrypt, s_line)
                if plaintext == '':
                    print 'Some secrets were modified or key is not valid! Please retry or restore your backup file!'
                    exit()
                line = line.replace(to_decrypt, plaintext)
                output.write(line)
            line = secrets.readline()
        output.close()
        s_file.close()
        if delete:
            try:
                remove(input_filename)
            except OSError, e:
                print "Error: %s - %s." % (e.filename, e.strerror) 