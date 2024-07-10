# Description
This python script is a possible solution to reverse the SHA256 
hash value! But there is 
a headache of huge time complexity. So we need a very very 
powerful processor (maybe doesn't exist yet) to complete 
this script within a desired runtime. Its actually brute-force
underneath.



# How It Works


## Basic Understanding

The SHA256 algorithm initially has 8 fixed values which here are denoted using: h0, h1, h2, h3, h4, h5, h6, h7. Then, it assigns these values to a, b, c, d, e, f, g, h respectively. For 1-55 characters ASCII input strings, the SHA265 algorithm mutates these values (a-h) 64 times, and in each loop the value of h is lost. Also, if the length of the input character is more than 55, then the values of h0 - h7 are also lost. How many values are really lost depends on the  length of the input characters.

- list_of_h represents the list of lost values of 'h'.
- list_of_h_num represents the list of lost values of 'h0'-'h7'
- chunk_size represents the length of input characters. 


## The Algorithm

```python
1. Ask to enter the produced hash value.

2. Ask to enter the chunk_size [Chunk Size represents the length of the input string that produced the hash value. 
If the length of the input string is between 1-55 characters, the Chunk Size is 1, if it is between 56-119, 
Chunk Size  is 2 and So on [64xn - 9]. However, If someone doesn't know the chunk size, he/she has to type 0.

3. Make a list (raw_list) of 4293967296 integer values [range(1000000, 4294967296)] by looping.

4. If chunk_size > 1:
      Make a new list (h_num_numbers_raw) from raw_list, deleting all the 7 digit values from raw_list.
      Make a new list (list_for_h_num_raw) using PERMUTATION from h_num_numbers_raw taking 8 values for each item.
   Else:
      list_for_h_num_raw = []

5. Make another list (list_for_h_raw) using PERMUTATION from raw_list taking 64 values for each item.

6. Proceed to sha256_reverse_main() function with all the above values.

7. If chunk_size > 1:
	Make another list (list_for_h_num) using PERMUTATION from list_for_h_num_raw taking (chunk_size-1) items for each new item.
   Else:
	list_for_h_num is a list of eight fixed items.

8. Make another list (list_for_h) using PERMUTATION from list_for_h_raw taking (chunk_size) items for each new item.

9. For each item in list_for_h_num:
	For each item in list_for_h:
		proceed to sha256_reverse() function. This is the core function which actually does the reverse. But the catch is, 
    we have to give the right lists to perform the reverse accurately. Thats why we have to iterate over the huge 
    list_for_h_num and the huge list_for_h to find the correct combinations of h_num_list and h_list consecutively. 
    Whenever a correct combination is given, the function finds the  string that produced the hash; this function then 
    immediately returns and all the parent loops break and the result is printed as both string and Bytes data, 
    Bytes data is more accurate. 
```



# Testing (does it really work?)

To test this script, we'll deliberately feed the correct list of 'h' values (the values that are lost during SHA256 runtime, which we'll have to brute force in real case) to the functions. However, to get the lost values of 'h' for an input string, we have to use the SHA256 script (you can get a complete code from [here](https://github.com/keanemind/Python-SHA-256)) and modify a little. Or you can use the below snippet (the one I used to test):

```python
"""
This Python module is an implementation of the SHA-256 algorithm.
From https://github.com/keanemind/Python-SHA-256. 

And I have edited it a little to get the lost values (for chunk_size=1), 
for the purpose of testing.

"""

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

h_list=[] # this is the list where we'll capture the lost 'h' values

def generate_hash(message: bytearray) -> bytearray:
    """Return a SHA-256 hash from the message passed.
    The argument should be a bytes, bytearray, or
    string object."""

    if isinstance(message, str):
        message = bytearray(message, 'ascii')
    elif isinstance(message, bytes):
        message = bytearray(message)
    elif not isinstance(message, bytearray):
        raise TypeError

    # Padding
    length = len(message) * 8 # len(message) is number of BYTES!!!
    message.append(0x80)
    while (len(message) * 8 + 64) % 512 != 0:
        message.append(0x00)

    message += length.to_bytes(8, 'big') # pad to 8 bytes or 64 bits

    assert (len(message) * 8) % 512 == 0, "Padding did not complete properly!"

    # Parsing
    blocks = [] # contains 512-bit chunks of message
    for i in range(0, len(message), 64): # 64 bytes is 512 bits
        blocks.append(message[i:i+64])

    # Setting Initial Hash Value
    h0 = 0x6a09e667
    h1 = 0xbb67ae85
    h2 = 0x3c6ef372
    h3 = 0xa54ff53a
    h5 = 0x9b05688c
    h4 = 0x510e527f
    h6 = 0x1f83d9ab
    h7 = 0x5be0cd19

    # SHA-256 Hash Computation
    for message_block in blocks:
        # Prepare message schedule
        message_schedule = []
        for t in range(0, 64):
            if t <= 15:
                # adds the t'th 32 bit word of the block,
                # starting from leftmost word
                # 4 bytes at a time
                message_schedule.append(bytes(message_block[t*4:(t*4)+4]))
            else:
                term1 = _sigma1(int.from_bytes(message_schedule[t-2], 'big'))
                term2 = int.from_bytes(message_schedule[t-7], 'big')
                term3 = _sigma0(int.from_bytes(message_schedule[t-15], 'big'))
                term4 = int.from_bytes(message_schedule[t-16], 'big')

                # append a 4-byte byte object
                schedule = ((term1 + term2 + term3 + term4) % 2**32).to_bytes(4, 'big')
                message_schedule.append(schedule)

        assert len(message_schedule) == 64

        # Initialize working variables
        a = h0
        b = h1
        c = h2
        d = h3
        e = h4
        f = h5
        g = h6
        h = h7

        # Iterate for t=0 to 63
        for t in range(64):
            h_list.append(h) # appending the lost 'h' values
            t1 = ((h + _capsigma1(e) + _ch(e, f, g) + K[t] +
                   int.from_bytes(message_schedule[t], 'big')) % 2**32)

            t2 = (_capsigma0(a) + _maj(a, b, c)) % 2**32

            h = g
            g = f
            f = e
            e = (d + t1) % 2**32
            d = c
            c = b
            b = a
            a = (t1 + t2) % 2**32

        # Compute intermediate hash value
        h0 = (h0 + a) % 2**32
        h1 = (h1 + b) % 2**32
        h2 = (h2 + c) % 2**32
        h3 = (h3 + d) % 2**32
        h4 = (h4 + e) % 2**32
        h5 = (h5 + f) % 2**32
        h6 = (h6 + g) % 2**32
        h7 = (h7 + h) % 2**32

    return ((h0).to_bytes(4, 'big') + (h1).to_bytes(4, 'big') +
            (h2).to_bytes(4, 'big') + (h3).to_bytes(4, 'big') +
            (h4).to_bytes(4, 'big') + (h5).to_bytes(4, 'big') +
            (h6).to_bytes(4, 'big') + (h7).to_bytes(4, 'big'))

def _sigma0(num: int):
    """As defined in the specification."""
    num = (_rotate_right(num, 7) ^
           _rotate_right(num, 18) ^
           (num >> 3))
    return num

def _sigma1(num: int):
    """As defined in the specification."""
    num = (_rotate_right(num, 17) ^
           _rotate_right(num, 19) ^
           (num >> 10))
    return num

def _capsigma0(num: int):
    """As defined in the specification."""
    num = (_rotate_right(num, 2) ^
           _rotate_right(num, 13) ^
           _rotate_right(num, 22))
    return num

def _capsigma1(num: int):
    """As defined in the specification."""
    num = (_rotate_right(num, 6) ^
           _rotate_right(num, 11) ^
           _rotate_right(num, 25))
    return num

def _ch(x: int, y: int, z: int):
    """As defined in the specification."""
    return (x & y) ^ (~x & z)

def _maj(x: int, y: int, z: int):
    """As defined in the specification."""
    return (x & y) ^ (x & z) ^ (y & z)

def _rotate_right(num: int, shift: int, size: int = 32):
    """Rotate an integer right."""
    return (num >> shift) | (num << size - shift)

inputstr = input("Enter something - ")

if __name__ == "__main__":
    print(generate_hash(inputstr).hex())
    print(h_list)
 
```
The above snippet will ask you to enter a string for which it will produce a hash, also it will give you a list of all the lost values of 'h'. Please provide a string here not more than 55 characters (to keep the chunk_size=1). Now, we take the list and place it in our sha256_reverse.py file like below (in line 211) and also we're disabling all the brute force algorithms:

```python

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
    convert the octal values to integer values first
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
        """
        If the chunk_size is 1; then the values of 'h0'-'h7' are already known
        """
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

# raw_list = [x for x in range(1000000, 4294967296)]

#if chunk_size[0] != 1:
#    h_num_numbers_raw = raw_list[9000000:] # all possible values of 'h': 8 digits to 10 digits
#    list_for_h_num_raw = permutations(h_num_numbers_raw, 8)
#else:
#    list_for_h_num_raw = []


#h_numbers_raw = raw_list # all possible values of 'h': 7 digits to 10 digits
#list_for_h_raw = permutations(h_numbers_raw, 64)

"""
We have disabled the brute-finding of the 'h' and 'h0'-'h7' values above
"""
list_for_h_num_raw = []
list_for_h_raw = [[<the values>]] # We are giving the correct combination of 'h' values

for chunk_size in chunk_size:
    sha256_reverse_main(hash_value_hex, chunk_size, list_for_h_num_raw, list_for_h_raw)
    
    # Now, we wait untill it gets the value. The magic happens here! But the problem is the TREMENDOUS number of values in both the lists list_for_h_num and list_for_h.
    
    
```

Now, run the script, provide the hash and when asked for chunk_size, type 1 and enter.

As you can see, we just got our input string back! But in real cases, we don't know the lost 'h' values (64 values, if the chunk_size is 1. or more if chunk_size is greater). And in case of the chunk_size>1, the values of second 'h0'-'h7' are also lost and the total number of lost 'h' values are 128; also they have to be in the correct order too. The more the chunk_size increases the greater the complexity is.

So, we have no other way but to go through all the possible values and combinations!



# Comments
So, as you can see, this code works! But in real cases it has to brute-find one or more correct combinations of correct values. With the current technologies, this program may run forever to find one hash. But I am really very optimistic here. And why not? Just think about todays mere ESP32 chips, which nearly cost nothing, are way faster than the 20th century supercomputers! So, you never know what tomorrow will bring you. Who knows, maybe in the next couple of years or decades they will eventually invent a cpu powerful enough.



# Optimization
The runtime of this algorithm can be minimized if the 
numerical range of 'h' and 'h0'-'h7' is researched and 
minimized.

The lost values lie in the range of 1000000 to 2^32. I believe, with proper research on the lost values and their ocurrences, this code can be optimized.


