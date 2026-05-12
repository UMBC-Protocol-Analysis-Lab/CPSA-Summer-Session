import models
import fastapi
import json
import cryptography
import os

def m5_alice(state,message):

    if state['alice']['state'] == 0:
        # we don't even need to parse message lol
        state['alice']['state'] = 1
        key = state['alice']['my_p_key']
        return (state,{"content" : f"t:Hello|n:bob|t:this is|n:alice|t:send the flag encrypted under this asymetric key|k:{key}"})
    if state['alice']['state'] == 1:
        message = models.parse_message(message,"t|d")
        if message[0] == "here it is" and len(message[1]) == 346:
            p = models.asym_decrypt(state['alice']['my_s_key'],message[1])
            message_2 = models.parse_message(p,"t")
            if message_2[0] == "DawgCTF{C3RT1F13D_1NS3CUR3}":
                state['alice']['state'] = 2
                return (state,{})

        raise fastapi.HTTPException(status_code=400, detail="Invalid message")

    else:
        raise fastapi.HTTPException(status_code=400, detail="alice state finished")
       
def m5_bob(state,message):
    
    if state['bob']['state'] == 0:
        message = models.parse_message(message,"t|n|t|n|t|k")
        if (message[0] == "Hello" and 
           message[1] == "bob" and
           message[2] == "this is" and
           message[3] == "alice" and
           message[4] == "send the flag encrypted under this asymetric key") and len(message[5]) == 280:
            try:
                d = models.asym_encrypt(message[5],"t:DawgCTF{C3RT1F13D_1NS3CUR3}")
            except ValueError:
                raise fastapi.HTTPException(status_code=400, detail="Invalid message")
            state['bob']['state'] = 2
            return (state,{"content" : f"t:here it is|d:{d}"})

        else:
            raise fastapi.HTTPException(status_code=400, detail="Invalid message")

    else:
        raise fastapi.HTTPException(status_code=400, detail="bob state finished")


m5_init_dict = {
    "model" : 5,
    "alice": {
        "state" : 0,
        "my_name" : "alice",
        "my_p_key" : "",
        "my_s_key" : "",
        "o_name" : "bob"
        },
    "bob" : {
        "state" : 0,
        "my_name" : "bob",
        "o_p_key" : "",
        "o_name" : "alice"
    },
}

def m5_init_func():

    p_key,s_key = models.gen_rsa_key()

    m5_init_dict["alice"]["my_p_key"] = p_key
    m5_init_dict["alice"]["my_s_key"] = s_key

    return json.dumps(m5_init_dict)

