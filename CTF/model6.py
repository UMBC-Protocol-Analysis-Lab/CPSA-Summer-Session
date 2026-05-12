import models
import fastapi
import json
import cryptography
import os

def m6_alice(state,message):

    if state['alice']['state'] == 0:
     
        message = models.parse_message(message,f"k:{models.PUBKEY_LEN}|n|d:{models.SIG_LEN}")

        if not models.verify_cert(message[0],message[1],message[2]):
            raise fastapi.HTTPException(status_code=403, detail="Invalid cert")

        state['alice']['o_name'] = message[1]
        state['alice']['o_p_key'] = message[0]

        state['alice']['my_nonce'] = os.urandom(32).hex()

        final_data = models.asym_encrypt(
                state['alice']['o_p_key'],
                "d:"+state['alice']['my_nonce']+
                "|k:"+state['alice']['my_p_key']+
                "|n:"+state['alice']['my_name']+
                "|d:"+state['alice']['my_cert']
                )

        state['alice']['state'] = 1

        return (state,{"content" : f"d:{final_data}"})

    elif state['alice']['state'] == 1:

        message = models.parse_message(message,"d")

        message = models.asym_decrypt(state['alice']['my_s_key'],message[0])

        message = models.parse_message(message,"d:64|d:64")

        if message[0] != state['alice']['my_nonce']:
            raise fastapi.HTTPException(status_code=400, detail="Invalid nonce")

        state['alice']['o_nonce'] = message[1]

        final_data = models.asym_encrypt(state['alice']['o_p_key'],"d:"+state['alice']['o_nonce'])

        state['alice']['state'] = 2

        return (state,{"content" : f"d:{final_data}"})

    elif state['alice']['state'] == 2:
    
        key = models.hash_message(state['alice']['my_nonce'] + state['alice']['o_nonce'])

        message = models.parse_message(message,"d")
       
        message = models.decrypt_message(message[0],key,key[:24])

        message = models.parse_message(message,"t")
        
        if message[0] == "DawgCTF{FORM3RLY_S3CUR3}":
            return (state,{})
        else:
            raise fastapi.HTTPException(status_code=400, detail="Invalid message")

    else:
    
        raise fastapi.HTTPException(status_code=400, detail="alice state finished")
       
def m6_bob(state,message):
    
    if state['bob']['state'] == 0:
    
        state['bob']['state'] = 1
        key = state['bob']['my_p_key']
        cert = state['bob']['my_cert']
        name = state['bob']['my_name']
 
        return (state,{"content" : f"k:{key}|n:{name}|d:{cert}"}) 

    elif state['bob']['state'] == 1:

        message = models.parse_message(message,f"d")

        message = models.asym_decrypt(state['bob']['my_s_key'],message[0])

        message = models.parse_message(message,f"d:64|k:{models.PUBKEY_LEN}|n|d:{models.SIG_LEN}")

        if not models.verify_cert(message[1],message[2],message[3]):
            raise fastapi.HTTPException(status_code=403, detail="Invalid cert")

        state['bob']['o_name'] = message[2]
        state['bob']['o_p_key'] = message[1]
        state['bob']['o_nonce'] = message[0]
        state['bob']['my_nonce'] = os.urandom(32).hex()

        final_data = models.asym_encrypt(
                state['bob']['o_p_key'],
                "d:"+state['bob']['o_nonce']+
                "|d:"+state['bob']['my_nonce']
                )

        state['bob']['state'] = 2

        return (state,{"content" : f"d:{final_data}"})

    elif state['bob']['state'] == 2:

        message = models.parse_message(message,"d")

        message = models.asym_decrypt(state['bob']['my_s_key'],message[0])

        message = models.parse_message(message,"d:64")

        if message[0] != state['bob']['my_nonce']:
            raise fastapi.HTTPException(status_code=400, detail="Invalid nonce")

        if state['bob']['o_name'] != 'sneed':
            raise fastapi.HTTPException(status_code=403, detail=f"Sorry, I can only say this the sneed, not a city slicker like you")

        key = models.hash_message(state['bob']['o_nonce'] + state['bob']['my_nonce'])
        flag = "t:DawgCTF{FORM3RLY_S3CUR3}"
        final_data = models.encrypt_message(flag,key,key[:24])

        return (state,{"content" : f"d:{final_data}"})

    elif state['alice']['state'] == 3:
        raise fastapi.HTTPException(status_code=400, detail="alice state finished")



m6_init_dict = {
    "model" : 6,
    "alice": {
        "state" : 0,
        "my_name" : "sneed",
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
        "my_name" : "chuck",
        "my_p_key" : "",
        "my_s_key" : "",
        "o_p_key" : "",
        "my_cert" : "",
        "my_nonce" : "",
        "o_nonce" : "",
        "o_name" : ""
    },
}

def m6_init_func():
    
    p_key,s_key = models.gen_rsa_key()

    m6_init_dict["alice"]["my_p_key"] = p_key
    m6_init_dict["alice"]["my_s_key"] = s_key
    m6_init_dict["alice"]["my_cert"] = models.get_cert(p_key,"sneed")
       
    p_key,s_key = models.gen_rsa_key()

    m6_init_dict["bob"]["my_p_key"] = p_key
    m6_init_dict["bob"]["my_s_key"] = s_key
    m6_init_dict["bob"]["my_cert"] = models.get_cert(p_key,"chuck")

    return json.dumps(m6_init_dict)

