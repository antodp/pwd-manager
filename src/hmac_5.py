import hashlib

'''

Della Porta Antonio - 09/06/2018

HMAC implementation using hashlib module.

hmac_sign for the MAC generation
hmac_verify for the check of the input given MAC

'''

def hmac_sign(key, msg, hashfunc = 'sha256', hexadecimal = True):  
    ''' 

    hmac_sign method generates the signature (MAC) for the message in input using the key and the hash function desired.
    The hash functions needs be in hashlib.algorithms_guaranteed set (see help from python console).

    @key : string containing the secret key
    @msg : string containing the message to be signed
    @hashfunc : the needed hash function
    @hexadecimal : boolean value determining if return value has to be hashfunc.hexdigest() (hexadecimal value) or hashfunc.digest() (bytes value)
    
    '''


    #check if hashfunc is callable
    if not hashfunc in hashlib.algorithms_guaranteed:
        raise ValueError("hashfunc is not in algorithms_guaranteed set! (see hashlib.algorithms_guaranteed)")

    #checks on msg type and content
    if msg is None:
        raise ValueError("msg in <None> but expected to be a valid string")
    if not isinstance(msg, str):
        raise TypeError("msg is expected to be <str> got <%s>" % type(msg).__name__)
    
    #check on key type
    if not isinstance(key, str):
        raise TypeError("key is expected to be <str> got <%s>" % type(key).__name__)
     
    inner_hash = hashlib.new(hashfunc)
    outer_hash = hashlib.new(hashfunc)

    #key manipulation
    blocksize = inner_hash.block_size

    if len(key) > blocksize:
        key = hashlib.new(hashfunc).update(key).digest()
    key = key.ljust(blocksize, b'\0')

    o_key = ''.join(chr(ord(k) ^ 0x5c) for k in key)
    i_key = ''.join(chr(ord(k) ^ 0x36) for k in key)
    
    inner_hash.update(i_key)
    outer_hash.update(o_key)
    inner_hash.update(msg)
    outer_hash.update(inner_hash.digest())

    digest = ''
    if not hexadecimal:
        digest = outer_hash.digest()
    else:
        digest = outer_hash.hexdigest()
    
    return digest

def hmac_verify(key, msg, sign, hashfunc = 'sha256'):
    ''' 
    
    hmac_verify method verify the integrity of the message by comparing the input given MAC with the value of HMAC(key, msg)
    
    @key : string containing the secret key
    @msg : string containing the message
    @sign : signature that needs verification
    @hashfunc : the needed hash function 

    '''

    mac = hmac_sign(key, msg, hashfunc)
    return hmac_sign(key, mac, hashfunc) == hmac_sign(key, sign, hashfunc) 

