import models
import fastapi
import json
import cryptography
import os

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

def m4_alice(state,message):

    if state['alice']['state'] == 0:
        # we don't even need to parse message lol
        state['alice']['state'] = 1
        key = state['alice']['my_key']
        nonce = state['alice']['my_nonce']
        return (state,{"content" : f"t:Hello|n:bob|t:this is|n:alice|t:send me the flag encrypted under this symetric key and nonce|k:{key}|d:{nonce}"})
    if state['alice']['state'] == 1:
        message = models.parse_message(message,"t|d")
        if message[0] == "here it is" and len(message[1]) == 88:
            p = models.decrypt_message(message[1],state['alice']['my_key'],state['alice']['my_nonce'])
            message_2 = models.parse_message(p,"t")
            if message_2[0] == "DawgCTF{N0T_S0_S3CR3T_K3Y}":
                state['alice']['state'] = 2
                return (state,{})

        raise fastapi.HTTPException(status_code=400, detail="Invalid message")

    else:
        raise fastapi.HTTPException(status_code=400, detail="alice state finished")
       
def m4_bob(state,message):
    
    if state['bob']['state'] == 0:
        message = models.parse_message(message,"t|n|t|n|t|k|d")
        if (message[0] == "Hello" and 
           message[1] == "bob" and
           message[2] == "this is" and
           message[3] == "alice" and
           message[4] == "send me the flag encrypted under this symetric key and nonce" and
           len(message[5]) == 64 and
           len(message[6]) == 24):
            try:
                d = models.encrypt_message("t:DawgCTF{N0T_S0_S3CR3T_K3Y}",message[5],message[6])
            except ValueError:
                raise fastapi.HTTPException(status_code=400, detail="Invalid message")
            state['bob']['state'] = 2
            return (state,{"content" : f"t:here it is|d:{d}"})

        else:
            raise fastapi.HTTPException(status_code=400, detail="Invalid message")

    else:
        raise fastapi.HTTPException(status_code=400, detail="bob state finished")


m4_init_dict = {
    "model" : 4,
    "alice": {
        "state" : 0,
        "my_name" : "alice",
        "my_key" : "",
        "my_nonce" : "",
        "o_name" : "bob"
        },
    "bob" : {
        "state" : 0,
        "my_name" : "bob",
        "o_key" : "",
        "o_name" : "alice"
    },
}

def m4_init_func():

    m4_init_dict["alice"]["my_key"] = ChaCha20Poly1305.generate_key().hex()
    m4_init_dict["alice"]["my_nonce"] = os.urandom(12).hex()

    return json.dumps(m4_init_dict)

