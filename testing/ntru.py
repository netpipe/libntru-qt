import sys
import random

#https://medium.com/@noumanalikhan328/lattice-based-cryptography-for-beginners-unlocking-the-secrets-of-ntru-encryption-3454bec88d7f
# Fixed, given parameters
p = 3
q = 61
N = 100

#generating random values of g and phi, 
#following the moderate security parameters of NTRU.

g = [1] * 12 + [-1] * 12
random.shuffle(g)

phi = [1] * 5 + [-1] * 5
random.shuffle(phi)


#function to encrypt the message that is in polynomial coefficient form.

def encrypt(p,phi,pubKey, msg, q):  
    pPhi=[0]*len(phi)  #initialize an empty list equal to length of list 'phi', to save the product of p*phi
    for i in range(len(phi)):
        pPhi[i]=p*phi[i] #generating product p*phi


    pPhi_PubKey = convol(pPhi, pubKey, n=100, p=0) #performing convolution on product of p*phi and public key 'h'
    len_difference = len(pPhi_PubKey) - len(msg) #calulating length difference between msg and pPhi and PubKey convolution.

    if len_difference<0:

        pPhi_PubKey += ([0] * abs(len_difference)) #padding the pPhi and Pubkey convol list to match length of msg list


    else:

        msg += ([0] * len_difference) #padding the msg list length to match length of pPhi and Pubkey convol list


    encryptMsg = [0] * len(pPhi_PubKey) #initializing a list to save encrypted message

    for i in range(len(msg)): #last step of encryption
        encryptMsg [i]= pPhi_PubKey[i] + msg[i]
        encryptMsg [i]%=q

    return encryptMsg

#function to convert binary of the message st
# into representative polynomial coefficient form

def string_to_polynomial(message): 

    # Define the mapping from 3-bit blocks to polynomial coefficients
    block_to_coefficient = {
        "000": [0, 0],
        "001": [0, 1],
        "010": [0, -1],
        "011": [1, 0],
        "100": [1, 1],
        "101": [1, -1],
        "110": [-1, 0],
        "111": [-1, 1],
    }

    # Convert the input message into 3-bit blocks
    blocks = [message[i:i+3] for i in range(0, len(message), 3)]

    # Convert each 3-bit block into a pair of coefficients
    polynomial_coefficients = []
    for block in blocks:
        polynomial_coefficients.extend(block_to_coefficient[block])

    return polynomial_coefficients

#function to convert input message string into binary representation

def string_to_bits(message): 
    ascii_values = [ord(char) for char in message]
    binary_values = ['{0:08b}'.format(value) for value in ascii_values]
    bit_string = ''.join(binary_values)
    padding_length = len(bit_string) % 3
    if padding_length == 1:
        bit_string += '00'
    elif padding_length == 2:
        bit_string += '0'

    return bit_string

#function to read message 'msg', that is going to be encrypted.

def Read_Message(): 
    try:
        filename = input("Enter name of text file containing Message to be encrypted: ")

        with open(filename, 'r') as file:
            msg = file.readline().strip()

        return msg
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found.")
        sys.exit(1)

    except Exception as e:
        print(f"An error occurred: {e}")
        sys.exit(1)

#function to calculate the public key
def convol(Fq, g, n, q): 
    f = f + (n - len(f)) * [0]
    g = g + (n - len(g)) * [0]
    result = [0] * (n)
    # Computing circular convolution
    for k in range(n):
        for i in range(k + 1):
            result[k] += f[i] * g[k - i]
        for i in range(k + 1, n):
            result[k] += f[i] * g[n + k - i]

    for i in range (len(result)):

        if p != 0:
            result[i] = result[i] % p  #reducing modulo


    return result


#function to calculate multiplicative modular inverses Fp and Fq
def inverse(f, N, mod): 
    while True:
        xN1 = [-1] + [0] * (N - 1) + [1]  # This makes xN_1 to be the polynomial xN-1
        g, m, _ = polEEA(f, xN1, mod)  # m will be the inverse of f with respect to xN-1 mod p

        if len(g) > 1:
            f=m
            continue
        else:  # Divide the constant (i.e. g) away from the equation, i.e. from m, so that m becomes an inverse.
            m, _ = poldiv(m, g, mod)
            return m


#function to read private key 'f' from text file.
def Reading_Private_Key():  
    try:
        filename = input("Enter the name of the file containing the private key 'f': ")

        with open(filename, 'r') as file:
            f = file.read()

        f = eval(f)
        return f
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found.")
        sys.exit(1)

    except Exception as e:
        print(f"An error occurred while reading the private key: {e}")
        sys.exit(1)

def extended_gcd_with_coefficients(a, b):  #calculating EEA of polynomial coefficients
    if a == 0:
        return (b, 0, 1)
    else:
        g, m, n = extended_gcd_with_coefficients(b % a, a)
        return (g, n - (b // a) * m, m)

def intEEA(a, b):  #modified (adding logic to compute EEA for polynomial coefficients using above function
    g, m, n = extended_gcd_with_coefficients(a, b)
    return g, m, n

# Invert integer a modulo p. If gcd(a,p) != 0 returns 0.
def intinv(a,p):
    g, m, _ = intEEA(a,p)
    if g!=1:
        return 0
    else:
        return m

def reduce(a, p):
    f = [i%p for i in a]
    return trim_zero(f)

def poladd(a, b, p):
    global sum
    if len(a) >= len(b):
        sum = [ a[i] + b[i] for i in range(len(b)) ]
        sum += a[len(b):]
    if len(a) < len(b):
        sum = [ a[i] + b[i] for i in range(len(a)) ]
        sum += b[len(a):]
    return reduce(sum,p)

def polsub(a, b, p):
    b = [-b[i] for i in range(len(b))]
    if len(a) >= len(b):
        diff = [ a[i] + b[i] for i in range(len(b)) ]
        diff += a[len(b):]
    if len(a) < len(b):
        diff = [ a[i] + b[i] for i in range(len(a)) ]
        diff += b[len(a):]
    return reduce(diff,p)

# Return the product of polynomials a and b, mod p.
def polmul(a,b,p): #modified, wrote code for this to perform polynomial multiplication.
    prod = [0] * (len(a) + len(b) - 1);


    # Take every term of first polynomial
    for i in range(len(a)):

        # Multiply the current term of first polynomial with every term of second polynomial.
        for j in range(len(b)):
            prod[i + j] += a[i] * b[j]
    if p==0:
        return prod
    else:
        return reduce(prod,p)


def poldiv(a, b, p):
    quotient = [0]*len(a)
    lead_coeff = intinv(b[-1], p)
    while len(a) >= len(b) and a!=[0]:
        divisor = [0]* ( len(a)-len(b)) + [lead_coeff*a[-1]%p]
        subtrahend = polmul(b, divisor, p)
        quotient = poladd(quotient, divisor, p)
        a = polsub(a, subtrahend, p)
    return trim_zero(quotient), a

def trim_zero(a):
    while len(a) > 1 and a[-1] == 0:
        a.pop()
    return a
def polEEA(a, b, p):
    r, old_r = trim_zero(b), trim_zero(a)
    s, old_s = [0], [1]
    t, old_t = [1], [0]
    while r != [0]:
        quotient,_ = poldiv(old_r, r, p)
        temp_r = trim_zero(polsub(old_r, polmul(quotient, r, p), p))
        temp_s = trim_zero(polsub(old_s, polmul(quotient, s, p), p))
        temp_t = trim_zero(polsub(old_t, polmul(quotient, t, p), p))
        old_r, r = r, temp_r
        old_s, s = s, temp_s
        old_t, t = t, temp_t
    gcd = old_r
    m = old_s
    n = old_t
    return gcd, m, n

#function to calculate multiplicative modular inverses Fp and Fq

def inverse(f, N, mod): 
    while True:
        xN1 = [-1] + [0] * (N - 1) + [1]  
        g, m, _ = polEEA(f, xN1, mod)  

        if len(g) > 1:
            f=m
            continue
        else:  
            m, _ = poldiv(m, g, mod)
            return m

#function performing circular convolution on two polynomials, modulo X^N -1
# Ensure both polynomials have the same degree
def convol(f, g, n, p):  
    f = f + (n - len(f)) * [0]
    g = g + (n - len(g)) * [0]
    result = [0] * (n)
    # Computing circular convolution
    for k in range(n):
        for i in range(k + 1):
            result[k] += f[i] * g[k - i]
        for i in range(k + 1, n):
            result[k] += f[i] * g[n + k - i]

    for i in range (len(result)):

        if p != 0:
            result[i] = result[i] % p  #reducing modulo


    return result