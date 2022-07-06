"""
Description:
This algorithm below has the ability to reverse the SHA256 
hash value all the way to the input string! But there is 
a headache of huge time complexity. So we need a very very 
powerful processor (maybe doesn't exist yet) to complete 
this script within a desired runtime. I left it as a simple 
synchronous code for the next programmer - who has enough 
hardware capabilities - to modify this code according to 
his preferences (async, I/O, multiprocessing or whichever 
necessary)
"""



from itertools import permutations

def _capsigma0(num: int):
    num = (_rotate_right(num, 2) ^
           _rotate_right(num, 13) ^
           _rotate_right(num, 22))
    return num

def _capsigma1(num: int):
    num = (_rotate_right(num, 6) ^
           _rotate_right(num, 11) ^
           _rotate_right(num, 25))
    return num

def _ch(x: int, y: int, z: int):
    return (x & y) ^ (~x & z)

def _maj(x: int, y: int, z: int):
    return (x & y) ^ (x & z) ^ (y & z)

def _rotate_right(num: int, shift: int, size: int = 32):
    return (num >> shift) | (num << size - shift)

K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ]

def sha256_reverse(hash_value_hex, chunk_size, h_num_list, h_list):

    """
    convert the octal values from the hash to integer values first
    """
    h0 = int.from_bytes(bytes.fromhex(hash_value_hex[0:8]), "big")
    h1 = int.from_bytes(bytes.fromhex(hash_value_hex[8:16]), "big")
    h2 = int.from_bytes(bytes.fromhex(hash_value_hex[16:24]), "big")
    h3 = int.from_bytes(bytes.fromhex(hash_value_hex[24:32]), "big")
    h4 = int.from_bytes(bytes.fromhex(hash_value_hex[32:40]), "big")
    h5 = int.from_bytes(bytes.fromhex(hash_value_hex[40:48]), "big")
    h6 = int.from_bytes(bytes.fromhex(hash_value_hex[48:56]), "big")
    h7 = int.from_bytes(bytes.fromhex(hash_value_hex[56:64]), "big")

    message_schedule_list = []

    for i in range(0, chunk_size):

        """
        set the last values of a,b,c,d,e,f,g,h from h0,h1,h2,h3,h4,h5,h6,h7
        """
        a =  h0 - h_num_list[i][0]
        if a<0:
            a=a+(2**32)
        b =  h1 - h_num_list[i][1]
        if b<0:
            b=b+(2**32)
        c =  h2 - h_num_list[i][2]
        if c<0:
            c=c+(2**32)
        d =  h3 - h_num_list[i][3]
        if d<0:
            d=d+(2**32)
        e =  h4 - h_num_list[i][4]
        if e<0:
            e=e+(2**32)
        f =  h5 - h_num_list[i][5]
        if f<0:
            f=f+(2**32)
        g =  h6 - h_num_list[i][6]
        if g<0:
            g=g+(2**32)
        h =  h7 - h_num_list[i][7]
        if h<0:
            h=h+(2**32)

        
        message_schedule_list.insert(0, [])

        for t in range(63, -1, -1):

            """
            reverse-mutation of the values of a,b,c,d,e,f,g,h
            """
            a0 = a
            e0 = e
            a = b
            b = c
            c = d

            e = f
            f = g
            g = h

            t2 = (_capsigma0(a) + _maj(a, b, c)) % 2**32
            t1 = a0-t2
            while t1<0:
                t1=t1+2**32

            message_schedule_integer = t1 - (h_list[i][t] + _capsigma1(e) + _ch(e, f, g) + K[t])
            if message_schedule_integer<0:
                message_schedule_integer = message_schedule_integer + ((-message_schedule_integer//2**32)+1)*2**32
            message_schedule_list[0].append(message_schedule_integer)

            d = e0 - t1
            while d<0:
                d=d+2**32
            
            h = h_list[i][t]

        message_schedule_list[0].reverse()

        h0 = a
        h1 = b
        h2 = c
        h3 = d
        h4 = e
        h5 = f
        h6 = g
        h7 = h 

        if a == 0x6a09e667 and b == 0xbb67ae85 and c == 0x3c6ef372 and d == 0xa54ff53a and e == 0x510e527f and f == 0x9b05688c and g == 0x1f83d9ab and h == 0x5be0cd19:
            """
            If the reverse is found, then the below codes will be run
            """
            final_list = []
            final_str = ''
            for i in range(len(message_schedule_list)):
                for t in range(16):
                    bytes_chunk = (message_schedule_list[i][t]).to_bytes(8, byteorder='big')
                    final_list.append(bytes_chunk)
                    try:
                        str_chunk = bytes_chunk.decode('ascii')
                        final_str += str_chunk
                    except:
                        print(final_str, '- Here, at most 3 values from the last may not be seen. Don\'t worry, just look at the bytes data below (before x80, the endian value) to confirm and know the missing values, if any')
            
            print(final_list)
            print('Program is SUCCESSFUL!')
            return 'Found!'

def sha256_reverse_main(hash_value_hex, chunk_size, list_for_h_num_raw, list_for_h_raw):

    """
    this function sets the lists and calls the core function with 
    all possible combinations
    """

    if chunk_size>1:
        list_for_h_num = permutations(list_for_h_num_raw, chunk_size-1)
    else:
        list_for_h_num = [[[0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]]]

    list_for_h = permutations(list_for_h_raw, chunk_size)
    list_for_h = list(list_for_h)

    for h_num_list in list_for_h_num:

        value = 'still not found'

        h_num_list = list(h_num_list)
        h_num_list.append([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19])

        for h_list in list_for_h:
            value = sha256_reverse(hash_value_hex, chunk_size, h_num_list, h_list)
            if value == 'Found!':
                break
        
        if value == 'Found!':
            break
        
hash_value_hex = str(input('Enter the SHA256 hash value here - '))
print('')
chunk_size = [int(input('Enter Chunk Size (integer). Chunk Size represents the length of the input string that produced the hash value. If the length of the input string is between 1-55 characters, Chunk Size is 1, if it is between 56-119, Chunk Size is 2 and so on [64xn - 9]. However, If you do not know the chunk size, type 0 and press enter. [Caution: Choosing 0 can take HUGE amount of time to finish this program! So, you better know the chunk size before proceeding with this algorithm, this can save a whole lot of your time]- '))]
print('')
print('Waiting For Result......')
print('')

if chunk_size[0]==0:
    """
    If an user doesn't know the chunk size,
    we have to try all possible chunk sizes
    starting from 1
    """
    chunk_size = [x for x in range(1,101)] # If you want, you can increase the range of chunk_size. But beware about the time complexity. Only setting 100 items here could take more than 100 years!

raw_list = [x for x in range(1000000, 4294967296)]

if chunk_size[0] != 1:
    h_num_numbers_raw = raw_list[9000000:] # all possible values of 'h': 8 digits to 10 digits
    list_for_h_num_raw = permutations(h_num_numbers_raw, 8)
else:
    list_for_h_num_raw = []


h_numbers_raw = raw_list # all possible values of 'h': 7 digits to 10 digits
list_for_h_raw = permutations(h_numbers_raw, 64)


for chunk_size in chunk_size:
    sha256_reverse_main(hash_value_hex, chunk_size, list_for_h_num_raw, list_for_h_raw)
    
    # Now, we wait untill it gets the value. The magic happens here! But the problem is the TREMENDOUS number of values in both the lists list_for_h_num and list_for_h.


