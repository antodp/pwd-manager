'''
Della Porta Antonio - 18/06/2018

vigenere.py - Implementazione in python del cifrario di Vigenere
descr: In questa versione del cifrario, si lavora con un sub-set dei caratteri ASCII (33-126)

'''


def vigenere_enc(msg, key):

	'''

    Effettua la cifratura del testo con il cifrario di vigenere.
    La tabella di vigenere non viene calcolata, si affronta invece la cifratura come l'applicazione
    di un cifrario di cesare con chiavi multiple date dagli indici nell'alfabeto della chiave

    key = chiave (stringa)
    msg = messaggio da cifrare

    E(msg[i]) = cifrario_cesare(msg[i],key[i%len(key)])

	'''

	if type(key) is not str or key == '':
		print 'key deve essere una stringa non vuota'

	ret = ''

	for (char, i) in zip(msg, range(0, len(msg))):
		if char == ' ':
			ret += char
		else:
			r_key = ord(key[i%len(key)]) - 33
			r_ch = ord(char) - 33
			ret += chr((r_ch + r_key)%93 + 33)

	return ret


def vigenere_dec(cyphr, key):

	'''

    Effettua la decifratura del testo con il cifrario di vigenere.
    La tabella di vigenere non viene calcolata, si affronta invece la decifratura come l'applicazione
    di un cifrario di cesare con chiavi multiple date dagli indici nell'alfabeto della chiave

    key = chiave (stringa)
    msg = messaggio da cifrare

    E(cyphr[i]) = decifra_cesare(cyphr[i], key[i%len(key)])

	'''

	if type(key) is not str or key == '':
		print 'key deve essere una stringa non vuota'

	ret = ''

	for (char, i) in zip(cyphr, range(0, len(cyphr))):
		if char == ' ':
			ret += char
		else:
			r_key = ord(key[i%len(key)]) - 33
			r_ch = ord(char) - 33
			ret += chr((r_ch - r_key)%93 + 33)
	
	return ret