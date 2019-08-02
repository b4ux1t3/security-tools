import hashlib

####### HELPER FUNCTIONS #######
def load_file(file_name):
    f = open(file_name, 'rb')
    read = f.read()
    f.close()
    return read

def hash_sha256(data):
        sha256 = hashlib.sha256(data)
        return sha256.hexdigest()

def hash_md5(data):
    md5 = hashlib.md5(data)
    return md5.hexdigest()

def hash_sha1(data):
    sha1 = hashlib.sha1(data)
    return sha1.hexdigest()

def save_to_file(file_name, output, function):
    try:
        f = open(f'{file_name}.{function}', "w")
        f.write(output)
        f.close()
    except:
        print(f'Unable to save file: {file_name}.{function}')

# Pass in the flags for all functions vs one function, the list of digests, 
# whether or not we want a simple output, and which function to use
def generate_output(all_check, digests, simple, function, file_name):
    output = None

    # Check if the user wants a simple output or not.
    if simple:
        # Check if we have one or all digests
        if all_check:
            output = f'{digests[0]}\n{digests[1]}\n{digests[2]}'
        else:
            output = digests[0]

    # Otherwise, they want the full output.
    else:
        # Check again if we have one or all digests
        if all_check:
            output = f'Filename:\t{file_name}\nSHA256 Hash:\t{digests[0]}\nMD5 Hash:\t{digests[1]}\nSHA1 Hash:\t{digests[2]}'
        else:
            output = f'Filename:\t{file_name}\n{function.upper()} Hash:\t{digests[0]}'
    return output       

####### MAIN PROGRAM #######
if __name__ == '__main__':
    import os, argparse, sys
    parser = argparse.ArgumentParser(description='Hash a file using the desired hashing function.')

    parser.add_argument('-f', '--file', help='The file you would like to hash', required=True)

    # We have to pass in a hash function, or we can specify all, 
    # but _one_ of these must be passed
    functions = parser.add_mutually_exclusive_group(required=True)
    functions.add_argument('--sha256', action='store_true', help='Perform the SHA256 hash function.')
    functions.add_argument('--md5', action='store_true', help='Perform the MD5 hash function. WARNING: MD5 is not considered cryptographically secure.')
    functions.add_argument('--sha1', action='store_true', help='Perform the SHA1 hash function. WARNING: SHA1 is not considered cryptographically secure.')
    functions.add_argument('--all', action='store_true', help='Perform all implemented hash functions.')

    parser.add_argument('-s', '--simple', action='store_true', help="Only output the hash digest, not other data.")
    parser.add_argument('-o', '--output', action='store_true', help="Write the output to a file instead of to the commandline.")

    # This sticks our arguments in a dictionary, so we can look up arguments by name.
    args = vars(parser.parse_args())

    file_name = None
    data = None
    try:
        file_name = os.path.abspath(args['file'])
        data = load_file(file_name)

    except FileNotFoundError:
        print(f'File {file_name} not found')
    
    except Exception:
        parser.print_usage()

    if data != None:
        digests = []
        function = None

        # Check which function we are using.
        if args['sha256'] :
            digests.append(hash_sha256(data))
            function = 'sha256' 
        elif args['md5']:
            digests.append(hash_sha256(data))
            function = 'md5'
        elif args['sha1']:
            digests.append(hash_sha1(data))
            function = 'sha1'
        else:
            sha256_digest = hash_sha256(data)
            md5_digest = hash_md5(data)
            sha1_digest = hash_sha1(data)
            digests = [sha256_digest, md5_digest, sha1_digest]
            function = 'all'
        
        output = generate_output(args['all'], digests, args['simple'], function, file_name)
        # Check if user wants file output or not.
        if args['output']:
            save_to_file(os.path.basename(file_name), output, function)
        else:
            print(output)
        

        
