from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding

from cryptography.exceptions import InvalidSignature

import os
import fastapi

ca_pub_key = "30818902818100d883d9c7b2d384325b1a5fe87c706a1eddae0f23517c3addaa683cad9c70491812fc08777576644b561c2527c117c99c71c3f0e43f7b67a377f2ec19529c4aed22bd5a9b57a0f59216d59b1dc37090193e23dd3f0b0df9bd6d87194af4a2e245d074852e933c410c69e80a41b5f36ba12fbf8e7cf77651f9e57bde8d1bb4b3050203010001"

ca_priv_key = "30820278020100300d06092a864886f70d0101010500048202623082025e02010002818100d883d9c7b2d384325b1a5fe87c706a1eddae0f23517c3addaa683cad9c70491812fc08777576644b561c2527c117c99c71c3f0e43f7b67a377f2ec19529c4aed22bd5a9b57a0f59216d59b1dc37090193e23dd3f0b0df9bd6d87194af4a2e245d074852e933c410c69e80a41b5f36ba12fbf8e7cf77651f9e57bde8d1bb4b305020301000102818100afb7b253842a6dab808c9331d76c5473e06d97138eda47dc06a4ba3a1c3074e1f8e65ae8b887f135c318ec7eab136728749c1530e8e47a640cc13624070b993204a668288b9c4c61cfeca8712dc57620e76ff5364137fdf10c64bb38f9dbd64b5ed35281512ddd9711956723e089ca0e6bccd845ce35a1277c2841e4341e7201024100f9a678c806f0378f722bcb5cdf123ba341f7e1ab268437986a467f0060300d8576389e6a66ab76523df0e7f0802a127eb847430f07ec7bf691a266c36bfc3621024100de05a0c6c3820e172546f2c8bc85bd7dadb1d29df82543ba57c31905a69e74d6e447cb053acc0e9183b7403ab98ad79a619f341a19390467f42f6b994b985865024100f3098e81e4c74cbf983d6c50305636badbc8eee7c8aa64d93b74ffc4a4df82fa4fba14f6ae96f3ac62e2b959d7db9d7fc1f49622f6ead14f9c3dc6df2eac2d21024064e223cb0d3d444fca1571ee3a937ea5e3ce0048dd5f7965ebc8efcebc8615cb2b515ff3d162b55ff37cca07a5156ca06ea95b905c53a727e131c6ef9204f86d024100bf9693d00801299331764aa28fc73519924f693b90d6bbe818d85995830b5acdd62acdc92822ddf5e6b15bca5bfdbf0a4bbf546ace8c45375119d85c2caa3d7f"

PUBKEY_LEN = len(ca_pub_key)
PRIVKEY_LEN = len(ca_priv_key)
SIG_LEN = 256

# parses message into a list
# checks is against message format in form "t|n|..."
def parse_message(message,msg_format):
    m = message.split("|")
    if len(m) > 32:
        raise fastapi.HTTPException(status_code=400, detail=f"Too many feilds in message!")

    fmt = [i.split(":") if ":" in i else (i,"65536") for i in msg_format.split("|")]

    fmt = [(i[0],int(i[1])) for i in fmt]

    if len(fmt) != len(m):
        raise fastapi.HTTPException(status_code=400, detail=f"Invalid message") 

    l = []
    for i in range(len(m)):
        f = m[i].split(":")
        if len(f) != 2:
            #print("1-",f)
            raise fastapi.HTTPException(status_code=400, detail=f"Invalid feild at index {i}")
        if f[0].strip() not in ["t","n","k","d"]:
            #print("2-",f)
            raise fastapi.HTTPException(status_code=400, detail=f"Invalid feild at index {i}")
        if f[0].strip() != fmt[i][0] or (fmt[i][1] != 65536 and len(f[1].strip()) != fmt[i][1]):
            #print("3-",len(f[1]))
            raise fastapi.HTTPException(status_code=400, detail=f"Invalid feild at index {i}")

        l.append(f[1].strip())
    return l

# special parse just for encrpytion functions that allowed encrpyting messages
def enc_parse(message,symetric=False):
    m = message.split("|")
    if m[0].split(":")[0] != 'k':
        raise fastapi.HTTPException(status_code=400, detail=f"Invalid feild at index 0")
    key = m[0].split(":")[1]
    if symetric:
        if m[1].split(":")[0] != 'd':
            raise fastapi.HTTPException(status_code=400, detail=f"Invalid feild at index 1")
        if m[2].split(":")[0] != 't':
            raise fastapi.HTTPException(status_code=400, detail=f"Invalid feild at index 1")
        nonce = m[1].split(":")[1]

        m[2] = ":".join(m[2].split(":")[1:])
        
        text = "|".join(m[2:])

        return (key,nonce,text)
    else:
        if m[1].split(":")[0] != 't':
            raise fastapi.HTTPException(status_code=400, detail=f"Invalid feild at index 1")

        m[1] = ":".join(m[1].split(":")[1:])
        
        text = "|".join(m[1:])

        return (key,text)



def gen_rsa_key():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=1024,
    )

    s_key_hex = private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
    ).hex()
    p_key_hex = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.PKCS1,
    ).hex()
    return (p_key_hex,s_key_hex)

def hash_message(message):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(message.encode())
    return digest.finalize().hex()

def encrypt_message(message,key,nonce):
    try:
        chacha = ChaCha20Poly1305(bytes.fromhex(key))
        d = chacha.encrypt(bytes.fromhex(nonce),message.encode(),b"")
    except Exception as e:
        raise fastapi.HTTPException(status_code=400, detail="Invalid message")
    return d.hex()

def decrypt_message(c_text,key,nonce):
    try:
        chacha = ChaCha20Poly1305(bytes.fromhex(key))
        d = chacha.decrypt(bytes.fromhex(nonce),bytes.fromhex(c_text),b"")
    except Exception as e:
        raise fastapi.HTTPException(status_code=400, detail="Invalid message")
    return d.decode()

def asym_encrypt(key,message):
    try:
        t_key = os.urandom(32)
        t_non = os.urandom(12)
 
        sym_part = encrypt_message(message,t_key.hex(),t_non.hex()) 
       
        pub_key = serialization.load_der_public_key(bytes.fromhex(key))
        ciphertext = pub_key.encrypt(
            t_key + t_non,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except Exception as e:
        raise fastapi.HTTPException(status_code=400, detail="Invalid message")

    return ciphertext.hex() + sym_part

def asym_decrypt(key,message):
    try:
        key_part = message[:256]
        sym_part = message[256:]
 
        priv_key = serialization.load_der_private_key(bytes.fromhex(key),password=None)
        keys_plain = priv_key.decrypt(
            bytes.fromhex(key_part),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
 
        t_key = bytes(keys_plain[:32])
        t_non = bytes(keys_plain[32:])
 
        plaintext = decrypt_message(sym_part,t_key.hex(),t_non.hex())
    except Exception as e:
        raise fastapi.HTTPException(status_code=400, detail="Invalid message")

    return plaintext

def asym_sign(key,message):
    try:

        priv_key = serialization.load_der_private_key(bytes.fromhex(key),password=None)
        signature = priv_key.sign(
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    except Exception as e:
        raise fastapi.HTTPException(status_code=400, detail="Invalid message")

    return signature.hex()

def asym_verify(key,sig,orig):
    try:
        pub_key = serialization.load_der_public_key(bytes.fromhex(key))
        signature = pub_key.verify(
            bytes.fromhex(sig),
            orig.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    except InvalidSignature:
        return False
    except Exception as e:
        raise fastapi.HTTPException(status_code=400, detail="Invalid message")

    return True

def get_cert(key,name):

    to_sign = f"k:{key}|n:{name}"
    
    sig = asym_sign(ca_priv_key,to_sign)

    return sig

def verify_cert(key,name,sig):

    to_sign = f"k:{key}|n:{name}"
    
    ret = asym_verify(ca_pub_key,sig,to_sign)

    return ret
