import models
import fastapi
import json

def m2_alice(state,message):

    if state['alice']['state'] == 0:
        # we don't even need to parse message lol
        state['alice']['state'] = 1
        return (state,{"content" : f"t:Hello|n:bob|t:this is|n:alice|t:give me the flag"})
    if state['alice']['state'] == 1:
        message = models.parse_message(message,"t|t")
        if message[0] == "here it is" and message[1] == "DawgCTF{CH4NG3_0F_PL4N5}":
            state['alice']['state'] = 2
            return (state,{})
        else:
            raise fastapi.HTTPException(status_code=400, detail="Invalid message")

    else:
        raise fastapi.HTTPException(status_code=400, detail="alice state finished")
       
def m2_bob(state,message):
    
    if state['bob']['state'] == 0:
        message = models.parse_message(message,"t|n|t|n|t")
        if (message[0] == "Hello" and 
           message[1] == "bob" and
           message[2] == "this is" and
           message[3] == "charlie" and
           message[4] == "give me the flag"):
            state['bob']['state'] = 2
            return (state,{"content" : "t:here it is|t:DawgCTF{CH4NG3_0F_PL4N5}"})
        elif (message[0] == "Hello" and 
           message[1] == "bob" and
           message[2] == "this is" and
           message[3] == "alice" and
           message[4] == "give me the flag"):
            raise fastapi.HTTPException(status_code=401, detail="I can only give charlie the flag")
        else:
            raise fastapi.HTTPException(status_code=400, detail="Invalid message")

    else:
        raise fastapi.HTTPException(status_code=400, detail="alice state finished")


m2_init_string = json.dumps({
    "model" : 2,
    "alice": {
        "state" : 0,
        "my_name" : "alice",
        "o_name" : "bob"
        },
    "bob" : {
        "state" : 0,
        "my_name" : "bob",
        "o_name" : "alice"
    },
})

def m2_init_func():
    return m2_init_string
