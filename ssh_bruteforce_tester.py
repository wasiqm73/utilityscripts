import paramiko
import sys
import math
import random
import time
import threading
import os
from paramiko import DSSKey
from paramiko import RSAKey
import getopt

opts, args = getopt.getopt(sys.argv[1:],"",["ip=", "num_requests=", "time_between_requests=", "requests_per_tcp_session=", "cipher="])

print (opts)

dst_ip = ""
num_requests = 0
time_between_requests = 1000
requests_per_tcp_session = 1
cipher = "rsa"

for opt, arg in opts:
    if opt == "--ip":
        dst_ip = arg
    elif opt == "--num_requests":
        num_requests = arg
    elif opt == "--time_between_requests":
        time_between_requests = arg
    elif opt == "--requests_per_tcp_session":
        requests_per_tcp_session = arg
    elif opt == "--cipher":
        cipher = arg

print ("ip: %s, num_requests: %d, time_between_requests: %d, requests_per_tcp_session: %d, cipher: %s" % (dst_ip, int(num_requests),
                       long(time_between_requests), int(requests_per_tcp_session), cipher))

key_type_table = {
    'dsa': DSSKey,
    'rsa': RSAKey,
 }

keys = {}
keys['rsa'] = {}
keys['rsa'][1024]=[]
keys['rsa'][2048]=[]
keys['rsa'][4096]=[]
keys['dsa'] = {}
keys['dsa'][1024]=[]
keys['dsa'][2048]=[]
keys['dsa'][3072]=[]

def get_username():
    username_list = ["nsbefia", "kmghiugh", "milmnoal", "kqrstb", "huuvwzig",
              "abcdnd", "jefghnw", "jijkllai", "rmnoch", "mpqrhis", "dstuin",
              "clvwxaha", "kapyzyzma", "sabg", "mtcdcv", "thiefgu", "shij",
              "njklr", "lmnopn", "staqrh", "cshhel", "stuhare", "rvwrch", "taxyn",
              "alabcdm"]
    return username_list[random.randint(0, len(username_list) - 1)]

def generate_private_key(cipher, size):
    print("Generating private key: %s-%d" % (cipher, size))
    private_key = key_type_table[cipher].generate(bits=size)
    return private_key

def generate_private_keys(key_directory = None):
    #Generates two sets of each 1024, 2048 and 4096 bit keys. One set for RSA
    #and one for DSA.
    print("Generating private keys....")
    for cipher in keys.keys():
        if key_directory is None:
            key_directory = "./keys"
        for size in keys[cipher].keys():
            for i in range(0, 10):
                key_file = "{}/{}_{}_{}".format(key_directory, cipher, size, i)
                if os.path.exists(key_file):
                    keys[cipher][size].append(key_type_table[cipher].from_private_key_file(key_file))
                    continue
                key = generate_private_key(cipher, size)
                keys[cipher][size].append(key)
                if not os.path.exists(os.path.dirname(key_file)):
                    os.makedirs(os.path.dirname(key_file))
                key.write_private_key_file(key_file)
    print("Done Generating private keys.")
      

def check_keys():
    for cipher in keys.keys():
        for size in keys[cipher].keys():
            if len(keys[cipher][size]) < 10:
                return False
    return True

def get_private_key(cipher, size):
    if check_keys() == False:
        generate_private_keys()
    return keys[cipher][size][random.randint(0, len(keys[cipher][size]) - 1)]

def ssh_key_auth_request(host, port, username = None, key = None, cipher =
          "rsa", size = 1024, requests_per_tcp_session = 1, time_between_requests
          = 0):
    t = paramiko.Transport((host, port))
    t.start_client()

    if username is None:
        user = get_username()
    else:
        user = username

    for i in range(0, int(requests_per_tcp_session)):
        time.sleep(int(time_between_requests)/1000)
        try:
            if key is None:
                auth_key = get_private_key(cipher, size)
            else:
                auth_key = key

            t.auth_publickey(username=user, key=auth_key)
        except:
            type, value, traceback = sys.exc_info()
            print ("Auth failed: %s, %s, %s" % (type, value, traceback))
    t.close()

def ssh_key_brute_force(host, port, num_requests = 200, time_between_requests =
          0, requests_per_tcp_session = 1, cipher = "rsa", key_sizes = [1024, 2048]):
    threads = []
    for i in range(0, int(math.floor(int(num_requests)/int(requests_per_tcp_session)))):
        time.sleep(long(time_between_requests)/1000)
        t = threading.Thread(target = ssh_key_auth_request, args = (host, port,
              None, None, cipher, key_sizes[i % len(key_sizes)],
              requests_per_tcp_session, time_between_requests))
        t.start()
        threads.append(t)

    time.sleep(int(time_between_requests)/1000)
    if int(num_requests) % int(requests_per_tcp_session) != 0:
        t = threading.Thread(target = ssh_key_auth_request, args = (host, port,
              None, None, cipher, key_sizes[i % len(key_sizes)],
              requests_per_tcp_session, time_between_requests))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

generate_private_keys()
ssh_key_brute_force(dst_ip, 22, num_requests = int(num_requests),
          time_between_requests = long(time_between_requests),
          requests_per_tcp_session = int(requests_per_tcp_session), cipher = cipher, key_sizes = [4096])
