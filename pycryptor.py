from Crypto.Cipher import AES as aes
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode
from colored import fg, bg, attr
import time
import sys
import os

KEYFILENAME = 'encryption.key'

class Color:
  def red(text):
    return f'{fg(196)}{text}{attr(0)}'

  def yellow(text):
    return f'{fg(220)}{text}{attr(0)}'

  def green(text):
    return f'{fg(40)}{text}{attr(0)}'

  def blue(text):
    return f'{fg(27)}{text}{attr(0)}'

def createKey(size = 16):
  if size == 128: size = 16
  if size == 192: size = 24
  if size == 256: size = 32

  return get_random_bytes(size)

def createCipher(key):
  cipher = aes.new(key, aes.MODE_GCM)
  nonce = cipher.nonce

  return { 'cipher': cipher, 'nonce': nonce }

def scanDir(dir):
  if not os.path.isdir(dir): return

  datafiles = []

  for r, d, f in os.walk(dir):
    for filename in f:
      file = os.path.join(r, filename)
      if os.path.isfile(file):
        datafiles.append(file)

  return [datafiles, len(datafiles)]

def encrypt(key, file, header):
  enc = createCipher(key)
  cipher = enc['cipher']
  nonce = enc['nonce']

  cipher.update(bytes(header.encode()))

  print(f'[{Color.blue("#")}] Encrypting {Color.blue(file)}')

  try:
    f = open(file, 'rb')
  except:
    print(f'[{Color.yellow("!")}] Could not open {Color.yellow(file)} for encryption')
    return

  data = f.read()
  f.close()

  cipherdata, tag = cipher.encrypt_and_digest(data)

  try:
    f = open(file, 'w')
  except:
    print(f'[{Color.yellow("!")}] Could not open {Color.yellow(file)} for encryption')
    return

  f.write(f'{str(b64encode(nonce))[2:-1]}\n')
  f.write(f'{str(b64encode(cipherdata))[2:-1]}\n')
  f.write(f'{str(b64encode(tag))[2:-1]}\n')

  f.close()

def encryption(target, keySize, header):
  startTime = time.process_time()

  if keySize == None:
    key = createKey(16)
  else:
    key = createKey(int(keySize))

  if os.path.isdir(target):
    datafiles = scanDir(target)[0]

    for file in datafiles:
      encrypt(key, file, header)

  elif os.path.isfile(target):
    datafile = target
    encrypt(key, datafile, header)

  else:
    print(f'[{Color.red("-")}] Invalid target')
    return

  f = open(KEYFILENAME, 'w')
  f.write(str(b64encode(key))[2:-1])
  f.close()

  print(f'[{Color.green("+")}] Key written to {Color.green(KEYFILENAME)} file')

  elapsed = time.process_time() - startTime
  if float(elapsed) > 0.1:
    print(f'[{Color.green("+")}] Encryption done in {elapsed} sec (CPU time)\n')
  else:
    print(f'[{Color.green("+")}] Encryption done!\n')

def decrypt(keyfile, file, header):
  try:
    f = open(file, 'r')
    nonce = b64decode(f.readline())
    cipherdata = b64decode(f.readline())
    tag = b64decode(f.readline())
    f.close()
  except:
    print(f'[{Color.yellow("!")}] Could not open {Color.yellow(file)} for encryption')
    return

  try:
    f = open(keyfile, 'r')
    key = b64decode(f.read())
    f.close()
  except:
    print(f'[{Color.red("-")}] Could not open {Color.yellow(keyfile)} key file')
    exit()

  cipher = aes.new(key, aes.MODE_GCM, nonce)
  cipher.update(bytes(header.encode()))

  print(f'[{Color.blue("#")}] Decrypting {Color.blue(file)}')
  data = cipher.decrypt(cipherdata)

  try:
    cipher.verify(tag)
    f = open(file, 'wb')
    f.write(data)
    f.close()
  except:
    print(f'[{Color.red("-")}] Could not decrypt {Color.red(file)}')

def decryption(target, key, header):
  startTime = time.process_time()

  if os.path.isdir(target):
    datafiles = scanDir(target)[0]

    for file in datafiles:
      decrypt(key, file, header)

  elif os.path.isfile(target):
    datafile = target
    decrypt(key, datafile, header)

  else:
    print(f'[{Color.red("-")}] Invalid target')
    return

  try:
    os.remove(KEYFILENAME)
  except:
    pass

  elapsed = time.process_time() - startTime
  if float(elapsed) > 0.1:
    print(f'[{Color.green("+")}] Decryption done in {elapsed} sec (CPU time)\n')
  else:
    print(f'[{Color.green("+")}] Decryption done!\n')

def main():
  print('\nPyCryptor v1.0 by Candyy')
  print('use --help for more info')
  print('It is recommended to run PyCryptor with administrator rights/sudo due to the data corruption risk\n')

  USAGE = '''
    -e\tencryption
    -d\tdecryption
    -t\ttarget [file/dir]
    -h\theader/header file [header -> plaintext]
    -s\tkey size [bytes/bits] (16B = 128b, 24B = 192b, 32B = 256b)
    -k\tkey file\n
    example:
    encryption:\t./pycryptor.py -e -t file.dat -h "header" -s 192
    decryption:\t./pycryptor.py -d -t file.dat -h "header" -k encryption.key\n
  '''

  if '--help' in sys.argv:
    print(USAGE)
    return

  if '-e' not in sys.argv and '-d' not in sys.argv:
    print(f'[{Color.yellow("#")}] Specify -e (encryption) OR -d (decryption)')
    return
  if '-e' in sys.argv and '-d' in sys.argv:
    print(f'[{Color.yellow("#")}] Specify encryption (-e) OR decryption (-d)')
    return
  if '-t' not in sys.argv:
    print(f'[{Color.yellow("#")}] Specify target (-t)')
    return
  if '-d' in sys.argv and '-k' not in sys.argv:
    print(f'[{Color.yellow("#")}] Specify key for decryption (-k)')
    return
  if '-h' not in sys.argv:
    print(f'[{Color.yellow("#")}] Specify -h (header)')
    return

  keySize = None
  header = None

  for arg in sys.argv:
    idx = sys.argv.index(arg)

    if arg == '-t':
      target = sys.argv[idx + 1]
      if target[:2] == '.\\': target = target[2:]
    if arg == '-k':
      keyfile = sys.argv[idx + 1]
    if arg == '-s':
      keySize = sys.argv[idx + 1]
    if arg == '-h':
      header = sys.argv[idx + 1]

  if '-e' in sys.argv:
    if os.path.isdir(target):
      datafilesCount = scanDir(target)[1]

    print(f'[{Color.yellow("!")}] WARNING!!! All data specified in file/dir after -t option will be encrypted using AES with GCM mode.')
    os.system('pause >nul')
    print(f'[{Color.yellow("!")}] WARNING!!! If you do not understand what an encryption is, stop it now.')
    os.system('pause >nul')
    print(f'[{Color.yellow("!")}] WARNING!!! Author of PyCryptor does not tak any responsibility in the case of corrupted data.')
    os.system('pause >nul')
    print(f'[{Color.yellow("!")}] WARNING!!! Your data will be nearly impossible to recover without {Color.yellow("header")} and {Color.yellow("key file")}. Remember this, and store this data in secure place.')
    os.system('pause >nul')
    if os.path.isdir(target):
      ans = input(f'[{Color.yellow("!")}] Are you aware of the danger, and yet, want to encrypt all data in {Color.yellow(target)} ({Color.yellow(datafilesCount)} files)? [y/n]: ')
    else:
      ans = input(f'[{Color.yellow("!")}] Are you aware of the danger, and yet, want to encrypt all data in {Color.yellow(target)}? [y/n]: ')

    if ans == 'y' or ans == 'Y':
      encryption(target, keySize, header)
    else:
      exit()

  if '-d' in sys.argv:
    decryption(target, keyfile, header)

if __name__ == '__main__': main()
