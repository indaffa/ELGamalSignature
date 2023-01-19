# ELGamalSignature
to run: pip install pycryptodome

to generate keys: python3 ElGamalsign.py -keygen

the keys will then be saved in keyfile.txt

to sign message: python3 ElGamalsign.py -sign -f message.txt

-f is the name of the message text
the signature is saved in a file called sign.txt

to verify: python3 ElGamalsign.py -sign -f message.txt -s sign.txt
