import models
import fastapi
import json
import cryptography
import os

def m7_alice(state,message):

    if state['alice']['state'] == 0:

        state['alice']['state'] = 1
        key = state['alice']['my_p_key']
        cert = state['alice']['my_cert']
        name = state['alice']['my_name']
        nonce = state['alice']['my_nonce']

        return (state,{"content" : f"k:{key}|n:{name}|d:{cert}|d:{nonce}"}) 

    elif state['alice']['state'] == 1:

        message = models.parse_message(message,f"k:{models.PUBKEY_LEN}|n|d:{models.SIG_LEN}|d:64|d:{models.SIG_LEN}")

        if not models.verify_cert(message[0],message[1],message[2]):
            raise fastapi.HTTPException(status_code=403, detail="Invalid cert")

        state['alice']['o_name'] = message[1]
        state['alice']['o_p_key'] = message[0]
        state['alice']['o_nonce'] = message[3]

        if state['alice']['o_name'] == "bob":
            raise fastapi.HTTPException(status_code=400, detail="I'm not talking to Bob, Hmph!")

        o_name = state['alice']['o_name']
        o_nonce = state['alice']['o_nonce']
        my_nonce = state['alice']['my_nonce']

        if not models.asym_verify(
                state['alice']['o_p_key'],
                message[4],
                f"n:{o_name}|d:{o_nonce}|d:{my_nonce}"
            ):
            raise fastapi.HTTPException(status_code=403, detail="Invalid signature")
           
        final_data = models.asym_sign(
                state['alice']['my_s_key'],
                "n:"+state['alice']['my_name']+
                "|d:"+state['alice']['o_nonce']+
                "|d:"+state['alice']['my_nonce']
                )

        state['alice']['state'] = 2

        return (state,{"content" : f"d:{final_data}"})

    elif state['alice']['state'] == 2:

        state['alice']['state'] = 3

        return (state,{})

    else:
    
        raise fastapi.HTTPException(status_code=400, detail="alice state finished")
       
def m7_bob(state,message):
    
    if state['bob']['state'] == 0:

        message = models.parse_message(message,f"k:{models.PUBKEY_LEN}|n|d:{models.SIG_LEN}|d:64")

        if not models.verify_cert(message[0],message[1],message[2]):
            raise fastapi.HTTPException(status_code=403, detail="Invalid cert")

        state['bob']['o_name'] = message[1]
        state['bob']['o_p_key'] = message[0]
        state['bob']['o_nonce'] = message[3]

        sig_data = models.asym_sign(
                state['bob']['my_s_key'],
                "n:"+state['bob']['my_name']+
                "|d:"+state['bob']['my_nonce']+
                "|d:"+state['bob']['o_nonce']
                )

        state['bob']['state'] = 1

        key = state['bob']['my_p_key']
        cert = state['bob']['my_cert']
        name = state['bob']['my_name']
        nonce = state['bob']['my_nonce']

        return (state,{"content" : f"k:{key}|n:{name}|d:{cert}|d:{nonce}|d:{sig_data}"})

    elif state['bob']['state'] == 1:

        message = models.parse_message(message,"d")

        o_name = state['bob']['o_name']
        o_nonce = state['bob']['o_nonce']
        my_nonce = state['bob']['my_nonce']

        if not models.asym_verify(
                state['bob']['o_p_key'],
                message[0],
                f"n:{o_name}|d:{my_nonce}|d:{o_nonce}"
            ):
            raise fastapi.HTTPException(status_code=403, detail="Invalid signature")

        if state['bob']['o_name'] != 'alice':
            raise fastapi.HTTPException(status_code=403, detail=f"I'm only saying this to Alice!")

        flag = "t:DawgCTF{F33L1NG_1NS3CUR3}"

        state['bob']['state'] = 2      

        return (state,{"content" : flag})

    elif state['alice']['state'] == 2:
        raise fastapi.HTTPException(status_code=400, detail="alice state finished")



m7_init_dict = {
    "model" : 7,
    "alice": {
        "state" : 0,
        "my_name" : "alice",
        "my_p_key" : "",
        "my_s_key" : "",
        "o_p_key" : "",
        "my_cert" : "",
        "my_nonce" : "",
        "o_nonce" : "",
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
        "o_name" : ""
    },
}

def m7_init_func():
    
    p_key,s_key = models.gen_rsa_key()

    m7_init_dict["alice"]["my_p_key"] = p_key
    m7_init_dict["alice"]["my_s_key"] = s_key
    m7_init_dict["alice"]["my_cert"] = models.get_cert(p_key,"alice")
    m7_init_dict["alice"]["my_nonce"]  = os.urandom(32).hex()
       
    p_key,s_key = models.gen_rsa_key()

    m7_init_dict["bob"]["my_p_key"] = p_key
    m7_init_dict["bob"]["my_s_key"] = s_key
    m7_init_dict["bob"]["my_cert"] = models.get_cert(p_key,"bob")
    m7_init_dict["bob"]["my_nonce"]  = os.urandom(32).hex()

    return json.dumps(m7_init_dict)

