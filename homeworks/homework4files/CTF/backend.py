import fastapi
import sqlite3
import random
import time
import json
from pydantic import BaseModel

import models as model_funcs
import model1
import model2
import model3
import model4
import model5
import model6
import model7
import model8
import model9

models = [
            (
                model1.m1_init_func,
                model1.m1_alice,
                model1.m1_bob
            ),
            (
                model2.m2_init_func,
                model2.m2_alice,
                model2.m2_bob
            ),
            (
                model3.m3_init_func,
                model3.m3_alice,
                model3.m3_bob
            ),
            (
                model4.m4_init_func,
                model4.m4_alice,
                model4.m4_bob
            ),
            (
                model5.m5_init_func,
                model5.m5_alice,
                model5.m5_bob
            ),
            (
                model6.m6_init_func,
                model6.m6_alice,
                model6.m6_bob
            ),
            (
                model7.m7_init_func,
                model7.m7_alice,
                model7.m7_bob
            ),
            (
                model8.m8_init_func,
                model8.m8_alice,
                model8.m8_bob
            ),
            (
                model9.m9_init_func,
                model9.m9_alice,
                model9.m9_bob
            ),
        ]

ALICE = 1
BOB = 2

#sqlite3.sqlite3_config(SQLITE_CONFIG_SERIALIZED)

con_t = sqlite3.connect('ramdisk/sessions.db',check_same_thread=False)

cur = con_t.cursor()

cur.execute("""
CREATE TABLE IF NOT EXISTS sessions (id INTEGER PRIMARY KEY, state TEXT, created INTEGER)
""")

con_t.commit()

con_t.close()

# id is just key across requests
# state is where all the info is (stored as JSON)

app = fastapi.FastAPI()

class Message(BaseModel):
    conn_id : int
    content : str

# returns ID
def make_new_session(default_state):

    con = sqlite3.connect('ramdisk/sessions.db',check_same_thread=False)
    con.execute("PRAGMA busy_timeout = 10000")
    cur = con.cursor()
    
    created = int(time.time())

    t_id = random.randint(0,2**60)

    while cur.execute(f"SELECT id FROM sessions WHERE id = {t_id}").fetchone():
        t_id = random.randint(0,2**60)

    cur.execute(f"INSERT INTO sessions VALUES ({t_id},\'{default_state}\',{created})")

    con.commit()

    con.close()

    return t_id

@app.get("/")
def root():
    return {"message":"please read the docs"}

@app.post("/model/{model_no}")
def m_start(model_no : int):

    if model_no <= 0 or model_no > 9:
        raise fastapi.HTTPException(status_code=404, detail=f"No model num {model_no}")

    t_id = make_new_session(models[model_no - 1][0]())

    return {"conn_id" : t_id}

@app.post("/util/sym_decrypt")
def util_sym_decrypt(
        message : Message
        ):

    if len(message.content) > 2 ** 16:
        raise fastapi.HTTPException(status_code=400, detail=f"Request to large!")

    message = model_funcs.parse_message(message.content,"k|d|d")
    if (len(message[0]) == 64 and
        len(message[1]) == 24):
            dec_text = model_funcs.decrypt_message(message[2],message[0],message[1])
            return {"content" : f"{dec_text}"}
    else:
        raise fastapi.HTTPException(status_code=400, detail="Invalid message")

@app.post("/util/sym_encrypt")
def util_sym_encrypt(
        message : Message
        ):

    if len(message.content) > 2 ** 16:
        raise fastapi.HTTPException(status_code=400, detail=f"Request to large!")

    message = model_funcs.enc_parse(message.content,symetric=True)
    if (len(message[0]) == 64 and
        len(message[1]) == 24):
            enc_text = model_funcs.encrypt_message(message[2],message[0],message[1])
            return {"content" : f"d:{enc_text}"}
    else:
        raise fastapi.HTTPException(status_code=400, detail="Invalid message")

@app.post("/util/gen_asym_key_pair")
def util_gen_asym_key():
    p_key,s_key = model_funcs.gen_rsa_key()
    return {"content" : f"t:public|k:{p_key}|t:private|k:{s_key}"}

@app.post("/util/asym_decrypt")
def util_asym_decrypt(
        message : Message
        ):

    if len(message.content) > 2 ** 16:
        raise fastapi.HTTPException(status_code=400, detail=f"Request to large!")

    message = model_funcs.parse_message(message.content,"k|d")
    if (abs(len(message[0]) - model_funcs.PRIVKEY_LEN) < 12):
            dec_text = model_funcs.asym_decrypt(message[0],message[1])
            return {"content" : f"{dec_text}"}
    else:
        raise fastapi.HTTPException(status_code=400, detail="Invalid message")

@app.post("/util/asym_encrypt")
def util_asym_encrypt(
        message : Message
        ):

    if len(message.content) > 2 ** 16:
        raise fastapi.HTTPException(status_code=400, detail=f"Request to large!")

    message = model_funcs.enc_parse(message.content)
    
    if (len(message[0]) == model_funcs.PUBKEY_LEN):
            enc_text = model_funcs.asym_encrypt(message[0],message[1])
            return {"content" : f"d:{enc_text}"}
    else:
        raise fastapi.HTTPException(status_code=400, detail="Invalid message")

@app.post("/util/asym_sign")
def util_asym_sign(
        message : Message
        ):
    
    if len(message.content) > 2 ** 16:
        raise fastapi.HTTPException(status_code=400, detail=f"Request to large!")

    message = model_funcs.enc_parse(message.content)

    if (abs(len(message[0]) - model_funcs.PRIVKEY_LEN) < 12):
        sig = model_funcs.asym_sign(message[0],message[1])
        return {"content" : f"d:{sig}"}
    else:
        raise fastapi.HTTPException(status_code=400, detail="Invalid message")

@app.post("/util/asym_verify")
def util_asym_verify(
        message : Message
        ):

    if len(message.content) > 2 ** 16:
        raise fastapi.HTTPException(status_code=400, detail=f"Request to large!")

    message = model_funcs.enc_parse(message.content,symetric=True)
    if (len(message[0]) == model_funcs.PUBKEY_LEN and len(message[1]) == model_funcs.SIG_LEN):
        res = model_funcs.asym_verify(message[0],message[1],message[2])
        return {"content" : f"d:{res}"}
    else:
        raise fastapi.HTTPException(status_code=400, detail="Invalid message")

@app.post("/util/get_cert")
def util_get_cert(
        message : Message
        ):
    
    if len(message.content) > 2 ** 16:
        raise fastapi.HTTPException(status_code=400, detail=f"Request to large!")

    message = model_funcs.parse_message(message.content,f"k|n")

    if (len(message[0]) == model_funcs.PUBKEY_LEN):
        if len(message[1]) > 128:
            raise fastapi.HTTPException(status_code=400, detail=f"name to large!")

        if message[1] in ['alice','bob','sneed','chuck'] or ":" in message[1]:
            raise fastapi.HTTPException(status_code=400, detail=f"invalid name!")

        cert = model_funcs.get_cert(message[0],message[1])
        return {"content" : f"d:{cert}"}
    else:
        raise fastapi.HTTPException(status_code=400, detail="Invalid message")

@app.post("/util/verify_cert")
def util_verify_cert(
        message : Message
        ):
    
    if len(message.content) > 2 ** 16:
        raise fastapi.HTTPException(status_code=400, detail=f"Request to large!")

    message = model_funcs.parse_message(message.content,"k|n|d")
    if (len(message[0]) == model_funcs.PUBKEY_LEN and len(message[2]) == model_funcs.SIG_LEN):
        cert = model_funcs.verify_cert(message[0],message[1],message[2])
        return {"content" : f"d:{cert}"}
    else:
        raise fastapi.HTTPException(status_code=400, detail="Invalid message")

@app.post("/util/hash_text")
def util_hash_t(
        message : Message
        ):

    if len(message.content) > 2 ** 16:
        raise fastapi.HTTPException(status_code=400, detail=f"Request to large!")

    message = model_funcs.parse_message(message.content,"t")
    hash_text = model_funcs.hash_message(message[0])
    return {"content" : f"d:{hash_text}"}

@app.post("/util/hash_data")
def util_hash_d(
        message : Message
        ):

    if len(message.content) > 2 ** 16:
        raise fastapi.HTTPException(status_code=400, detail=f"Request to large!")

    message = model_funcs.parse_message(message.content,"d")
    enc_text = model_funcs.hash_message(message[0])
    return {"content" : f"d:{enc_text}"}

@app.post("/alice")
def alice_msg(
        message : Message
        ):

    con = sqlite3.connect('ramdisk/sessions.db',check_same_thread=False)
    con.execute("PRAGMA busy_timeout = 10000")
    cur = con.cursor()

    try:
        curr_state = cur.execute(f"SELECT state FROM sessions WHERE id = ?",(message.conn_id,)).fetchone()
    except sqlite3.InterfaceError:
        raise fastapi.HTTPException(status_code=400, detail=f"DB access error, possible invalid conn id {message.conn_id}")


    if curr_state == None:
        raise fastapi.HTTPException(status_code=404, detail=f"No session with id {message.conn_id}")

    if len(message.content) > 2 ** 16:
        raise fastapi.HTTPException(status_code=400, detail=f"Request to large!")

    try: 
        curr_state = json.loads(curr_state[0])
    except json.decoder.JSONDecodeError:
        raise fastapi.HTTPException(status_code=400, detail=f"Invalid Message")

    new_state,response = models[curr_state['model'] - 1][ALICE](curr_state,message.content)

    try:
        cur.execute("UPDATE sessions SET state = ? WHERE id = ?",(json.dumps(new_state),message.conn_id))
    except sqlite3.InterfaceError:
        raise fastapi.HTTPException(status_code=400, detail=f"DB access error, possible invalid conn id {message.conn_id}")

    con.commit()

    con.close()

    return response

@app.post("/bob")
def bob_msg(
        message : Message
        ):
    
    con = sqlite3.connect('ramdisk/sessions.db',check_same_thread=False)
    con.execute("PRAGMA busy_timeout = 10000")

    cur = con.cursor()

    try: 
        curr_state = cur.execute(f"SELECT state FROM sessions WHERE id = ?",(message.conn_id,)).fetchone()
    except sqlite3.InterfaceError:
        raise fastapi.HTTPException(status_code=400, detail=f"DB access error, possible invalid conn id {message.conn_id}")

    if curr_state == None:
        raise fastapi.HTTPException(status_code=404, detail=f"No session with id {message.conn_id}")

    if len(message.content) > 2 ** 16:
        raise fastapi.HTTPException(status_code=400, detail=f"Request to large!")

    try: 
        curr_state = json.loads(curr_state[0])
    except json.decoder.JSONDecodeError:
        #print(curr_state)
        raise fastapi.HTTPException(status_code=400, detail=f"Invalid Message")

    new_state,response = models[curr_state['model'] - 1][BOB](curr_state,message.content)

    try:
        cur.execute("UPDATE sessions SET state = ? WHERE id = ?",(json.dumps(new_state),message.conn_id))
    except sqlite3.InterfaceError:
        raise fastapi.HTTPException(status_code=400, detail=f"DB access error, possible invalid conn id {message.conn_id}")

    con.commit()

    con.close()

    return response


if __name__ == "__main__":
    import uvicorn
    try:
        uvicorn.run(
            "backend:app",
            host="0.0.0.0",
            port=443,  # HTTPS default port
            ssl_certfile="fullchain.pem",
            ssl_keyfile="privkey.pem"
        )
    except FileNotFoundError as e:
        print(f"SSL certificate or key not found: {e}")
    except Exception as e:
        print(f"Error starting server: {e}")


