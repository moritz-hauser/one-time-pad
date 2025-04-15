# one-time-pad
... cracking one-time-pad encryption for univie's "information security management"

## files
**cleartext\_test\_data.txt**
- contains cleartext that may be encrypted with encrypt.py.

**crack\_otp.py**
- contains the code to crack a one-time-pad encryption.

**cribs.txt**
- contains the cribs that were used to crack stage\_1.txt.

**dict.txt**
- contains an english wordlist based on [this](https://github.com/powerlanguage/word-lists/blob/master/1000-most-common-words.txt) with minor adjustments.

**encrypt.py**
- encrypts messages using a provided key with one-time-pad encryption.

**encrypted\_test\_data.txt**
- this is were encrypt.py writes to by default. 
- contains encrypted messages in an appropriate format suitable for decryption.

**key\_test.txt**
- contains a key that may be used with encrypt.py.

**stage\_1.txt**
- contains the courses encrypted messages.
- all programs were written with this file in mind.
- may be encrypted using crack_otp.py to reveal the flag.

## how to use
run script with default arguments (i.e. using the provided dict.txt and cribs.txt on stage\_1.txt):
```bash
python3 crack_otp.py -d
```
if you want to use other files, run without argument (program will ask for each file):
```bash
python3 crack_otp.py
```

if you want to try encrypting and decrypting yourself you can use encrypt.py.
encrypt a message using one-time-pad encryption (you can use cleartext\_test\_data.txt and key\_test.txt):
```bash
python3 encrypt.py [cleartext] [key]
```
this program writes to encrypted\_test\_data.txt. 
of course this is not a good way of encrypting (for reasons described below) and should not be used for actual sensitive information.
you can now try decrypting encrypted\_test\_data.txt with crack_otp.py as described above. make sure to edit cribs.txt as needed.

## background
this short program was written for univie's "information security management" course as a practical exercise on cracking insecure one-time-pad encryption.
the reason why the otherwise unbreakable otp encryption can be decrypted here is because the same key has been used on more than one message.
