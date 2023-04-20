import argparse
import hashlib
import base64
import datetime
import sys
from concurrent.futures import ThreadPoolExecutor


def seeyon_sm3_attack(wordlist, hash=None, hash_file=None):
    with open(wordlist, "r", encoding='UTF-8', errors='ignore') as infile:
        with ThreadPoolExecutor(max_workers=50) as executor:
            if hash:
                seeyon_sm3_attack_single(executor, hash, infile)
            elif hash_file:
                seeyon_sm3_attack_batch(executor, hash_file, infile)


def seeyon_sm3_attack_single(executor, hash, wordlist_file, exit_on_success=True):
    futures = []
    for p in wordlist_file:
        futures.append(executor.submit(seeyon_sm3_hash, hash.rstrip("\n"), p.strip(), exit_on_success))
    for future in futures:
        result = future.result()
        if result and exit_on_success:
            break


def seeyon_sm3_attack_batch(executor, hash_file, wordlist_file):
    with open(hash_file, "r", encoding='UTF-8', errors='ignore') as hashfile:
        for hash in hashfile:
            seeyon_sm3_attack_single(executor, hash.rstrip("\n"), wordlist_file, exit_on_success=False)
            wordlist_file.seek(0)


def seeyon_sm3_hash(hash, p, exit_on_success=True):
    if hash.find(":") > 0:
        user = hash.split(":")[0]
        passhash = hash.split(":")[1]
        if passhash.find("$SM3$") < 0:
            print("[!] Error: No hash-mode matches the structure of the input hash. ")
            print("[i] Hash Examples:\nsystem:$SM3$d6JilVXOg2l8K3FSqqTi015fYytCOdvCf+6gZdx5bOs= \n")
            sys.exit(0)
            return None
    else:
        print("[!] Error: No hash-mode matches the structure of the input hash.  \n")
        print("[i] Hash Examples:\nsystem:$SM3$d6JilVXOg2l8K3FSqqTi015fYytCOdvCf+6gZdx5bOs= \n")
        sys.exit(0)
        return None

    new_hash = passhash.replace('$SM3$', '')
    try:
        s1 = base64.b64decode(new_hash).hex()
    except:
        print("[!] Base64 Incorrect padding")
        print("[i] Hash Examples:\nsystem:$SM3$d6JilVXOg2l8K3FSqqTi015fYytCOdvCf+6gZdx5bOs=")
        sys.exit(0)
        return None

    new_sm3 = hashlib.new("SM3")
    w = str(user + p).encode("utf-8")
    new_sm3.update(w)
    c = new_sm3.hexdigest()

    if s1 == c:
        print("[*] Cracked: {}:{}:{}".format(user, passhash, p))
        if exit_on_success:
            sys.exit(0)
        return p
    return None


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Custom HASH Password recovery")
    parser.add_argument("-w", "--wordlist", required=True, help="wordlist")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--hash", help="hash")
    group.add_argument("--hash-file", help="hash file")
    args = parser.parse_args()
    kwargs = args.__dict__
    sm3 = hashlib.new("SM3")
    start_time = datetime.datetime.now()
    seeyon_sm3_attack(**kwargs)
    end_time = datetime.datetime.now()
    time_diff = end_time - start_time
    time_diff_seconds = time_diff.seconds
    print('The total time consuming {0} minutes {1} seconds '.format(int(time_diff_seconds / 60),
                                                                      int(time_diff_seconds % 60)))
