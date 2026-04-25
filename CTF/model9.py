import models
import fastapi
import json
import cryptography
import os

def m9_alice(state,message):

    if state['alice']['state'] == 0:

        state['alice']['state'] = 1
        key = state['alice']['my_p_key']
        cert = state['alice']['my_cert']
        name = state['alice']['my_name']

        return (state,{"content" : f"k:{key}|n:{name}|d:{cert}"}) 

    elif state['alice']['state'] == 1:

        message = models.parse_message(message,f"k:{models.PUBKEY_LEN}|n|d:{models.SIG_LEN}|d|n")
        
        if message[4] != state['alice']['my_name']:
            raise fastapi.HTTPException(status_code=400, detail="This message wasn't addressed to me")

        if not models.verify_cert(message[0],message[1],message[2]):
            raise fastapi.HTTPException(status_code=403, detail="Invalid cert")


        state['alice']['o_p_key'] = message[0]
        state['alice']['o_name'] = message[1]

        message = models.asym_decrypt(
                state['alice']['my_s_key'],
                message[3],
                )
        
        message = models.parse_message(message,f"d|n")
        
        if message[1] != state['alice']['o_name']:
            raise fastapi.HTTPException(status_code=400, detail="Inner and outer names don't match")
       
        message = models.asym_decrypt(
                state['alice']['my_s_key'],
                message[0],
                )

        final_buf = models.asym_encrypt(
                state['alice']['o_p_key'],
                message,
                )

        final_buf = models.asym_encrypt(
                state['alice']['o_p_key'],
                f"d:{final_buf}|n:{state['alice']['my_name']}",
                )       
       
        key = state['alice']['my_p_key']
        cert = state['alice']['my_cert']
        name = state['alice']['my_name']
        o_name = state['alice']['o_name']

        # we don't advance state since we need to do this several times to win
        #state['alice']['state'] = 2

        return (state,{"content" : f"k:{key}|n:{name}|d:{cert}|d:{final_buf}|n:{o_name}"})

    else:
    
        raise fastapi.HTTPException(status_code=400, detail="alice state finished")
       
def m9_bob(state,message):

    if state['bob']['state'] == 0:

        message = models.parse_message(message,f"k:{models.PUBKEY_LEN}|n|d:{models.SIG_LEN}")

        if not models.verify_cert(message[0],message[1],message[2]):
            raise fastapi.HTTPException(status_code=403, detail="Invalid cert")

        if message[1] != "alice":
            raise fastapi.HTTPException(status_code=403, detail="I can only give this to alice, sorry!")

        state['bob']['o_p_key'] = message[0]
        state['bob']['o_name'] = message[1]

        final_buf = models.asym_encrypt(
                state['bob']['o_p_key'],
                "t:DawgCTF{ST4R3_1NTO_TH3_VO1D}",
                )

        final_buf = models.asym_encrypt(
                state['bob']['o_p_key'],
                f"d:{final_buf}|n:{state['bob']['my_name']}",
                )       
       
        key = state['bob']['my_p_key']
        cert = state['bob']['my_cert']
        name = state['bob']['my_name']
        o_name = state['bob']['o_name']

        # we don't advance state since we need to do this several times to win
        state['bob']['state'] = 1

        return (state,{"content" : f"k:{key}|n:{name}|d:{cert}|d:{final_buf}|n:{o_name}"})


    else:
    
        raise fastapi.HTTPException(status_code=400, detail="alice state finished")


m9_init_dict = {
    "model" : 9,
    "alice": {
        "state" : 0,
        "my_name" : "alice",
        "my_p_key" : "",
        "my_s_key" : "",
        "o_p_key" : "",
        "my_cert" : "",
        "o_name" : ""
        },
    "bob" : {
        "state" : 0,
        "my_name" : "bob",
        "my_p_key" : "",
        "my_s_key" : "",
        "o_p_key" : "",
        "my_cert" : "",
        "o_name" : ""
    },
}

def m9_init_func():
    
    p_key,s_key = models.gen_rsa_key()

    m9_init_dict["alice"]["my_p_key"] = p_key
    m9_init_dict["alice"]["my_s_key"] = s_key
    m9_init_dict["alice"]["my_cert"] = models.get_cert(p_key,"alice")

    p_key,s_key = models.gen_rsa_key()

    m9_init_dict["bob"]["my_p_key"] = p_key
    m9_init_dict["bob"]["my_s_key"] = s_key
    m9_init_dict["bob"]["my_cert"] = models.get_cert(p_key,"bob")

    return json.dumps(m9_init_dict)

