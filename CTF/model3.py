import models
import fastapi
import json

def m3_alice(state,message):
    raise fastapi.HTTPException(status_code=404, detail="No alice here, sorry!")
       
def m3_bob(state,message):
    
    if state['bob']['state'] == 0:
        message = models.parse_message(message,"t|n|t|n|t")
        if (message[0] == "Hello" and 
           message[1] == "bob" and
           message[2] == "this is" and
           message[3] == "alice" and
           message[4] == "give me the flag"):
            state['bob']['state'] = 2
            return (state,{"content" : "t:here it is|t:DawgCTF{N0_0N3_3LS3_H0M3}"})
        else:
            raise fastapi.HTTPException(status_code=400, detail="Invalid message")

    else:
        raise fastapi.HTTPException(status_code=400, detail="alice state finished")


m3_init_string = json.dumps({
    "model" : 3,
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

def m3_init_func():
    return m3_init_string
