import models
import fastapi
import json
import cryptography
import os

def m8_alice(state,message):

    if state['alice']['state'] == 0:

        state['alice']['state'] = 1
        key = state['alice']['my_p_key']
        cert = state['alice']['my_cert']
        name = state['alice']['my_name']

        return (state,{"content" : f"k:{key}|n:{name}|d:{cert}"}) 

    elif state['alice']['state'] == 1:

        message = models.parse_message(message,f"k:{models.PUBKEY_LEN}|n|d:{models.SIG_LEN}|d:64")

        if not models.verify_cert(message[0],message[1],message[2]):
            raise fastapi.HTTPException(status_code=403, detail="Invalid cert")

        state['alice']['o_name'] = message[1]
        state['alice']['o_p_key'] = message[0]
        state['alice']['o_nonce'] = message[3]

        o_name = state['alice']['o_name']
        o_nonce = state['alice']['o_nonce']
        my_nonce = state['alice']['my_nonce']

        sig = models.asym_sign(
                state['alice']['my_s_key'],
                f"n:{o_name}|d:{o_nonce}|d:{my_nonce}"
            )
           
        state['alice']['state'] = 2

        return (state,{"content" : f"d:{my_nonce}|d:{sig}"})

    elif state['alice']['state'] == 2:

        message = models.parse_message(message,f"d:64|d:{models.SIG_LEN}")

        state['alice']['o_nonce2'] = message[0]

        my_name = state['alice']['my_name']
        o_nonce2 = state['alice']['o_nonce2']
        my_nonce = state['alice']['my_nonce']

        if not models.asym_verify(
                state['alice']['o_p_key'],
                message[1],
                f"n:{my_name}|d:{my_nonce}|d:{o_nonce2}"
                ):
            raise fastapi.HTTPException(status_code=403, detail="Invalid sig")
 
        state['alice']['state'] = 3

        return (state,{"content" : "t:Thanks, but I don't have anything to tell you!"})

    else:
    
        raise fastapi.HTTPException(status_code=400, detail="alice state finished")
       
def m8_bob(state,message):

    if state['bob']['state'] == 0:

        state['bob']['state'] = 1
        key = state['bob']['my_p_key']
        cert = state['bob']['my_cert']
        name = state['bob']['my_name']

        return (state,{"content" : f"k:{key}|n:{name}|d:{cert}"}) 

    elif state['bob']['state'] == 1:

        message = models.parse_message(message,f"k:{models.PUBKEY_LEN}|n|d:{models.SIG_LEN}|d:64")

        if not models.verify_cert(message[0],message[1],message[2]):
            raise fastapi.HTTPException(status_code=403, detail="Invalid cert")

        state['bob']['o_name'] = message[1]
        state['bob']['o_p_key'] = message[0]
        state['bob']['o_nonce'] = message[3]

        o_name = state['bob']['o_name']
        o_nonce = state['bob']['o_nonce']
        my_nonce = state['bob']['my_nonce']

        sig = models.asym_sign(
                state['bob']['my_s_key'],
                f"n:{o_name}|d:{o_nonce}|d:{my_nonce}"
            )
           
        state['bob']['state'] = 2

        return (state,{"content" : f"d:{my_nonce}|d:{sig}"})

    elif state['bob']['state'] == 2:

        message = models.parse_message(message,f"d:64|d:{models.SIG_LEN}")

        state['bob']['o_nonce2'] = message[0]

        my_name = state['bob']['my_name']
        o_nonce2 = state['bob']['o_nonce2']
        my_nonce = state['bob']['my_nonce']

        if not models.asym_verify(
                state['bob']['o_p_key'],
                message[1],
                f"n:{my_name}|d:{my_nonce}|d:{o_nonce2}"
                ):
            raise fastapi.HTTPException(status_code=403, detail="Invalid sig")
 
        state['bob']['state'] = 3

        return (state,{"content" : "t:DawgCTF{4SK_4ND_U_SH4LL_R3C31V3}"})

    else:
    
        raise fastapi.HTTPException(status_code=400, detail="alice state finished")


m8_init_dict = {
    "model" : 8,
    "alice": {
        "state" : 0,
        "my_name" : "alice",
        "my_p_key" : "",
        "my_s_key" : "",
        "o_p_key" : "",
        "my_cert" : "",
        "my_nonce" : "",
        "o_nonce" : "",
        "o_nonce2" : "",
        "o_name" : ""
        },
    "bob" : {
        "state" : 0,
        "my_name" : "bob",
        "my_p_key" : "",
        "my_s_key" : "",
        "o_p_key" : "",
        "my_cert" : "",
        "my_nonce" : "",
        "o_nonce" : "",
        "o_nonce2" : "",
        "o_name" : ""
    },
}

def m8_init_func():
    
    p_key,s_key = models.gen_rsa_key()

    m8_init_dict["alice"]["my_p_key"] = p_key
    m8_init_dict["alice"]["my_s_key"] = s_key
    m8_init_dict["alice"]["my_cert"] = models.get_cert(p_key,"alice")
    m8_init_dict["alice"]["my_nonce"]  = os.urandom(32).hex()

    p_key,s_key = models.gen_rsa_key()

    m8_init_dict["bob"]["my_p_key"] = p_key
    m8_init_dict["bob"]["my_s_key"] = s_key
    m8_init_dict["bob"]["my_cert"] = models.get_cert(p_key,"bob")
    m8_init_dict["bob"]["my_nonce"]  = os.urandom(32).hex()

    return json.dumps(m8_init_dict)

