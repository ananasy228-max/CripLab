from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from typing import Optional
import base64
from Crypto.Random import get_random_bytes

# Импортируем функции
from cripta_protokol import (
    aes_encrypt_CBC, aes_decrypt_CBC,
    sha256_hash, md5_hash,
    base64_encode, base64_decode,
    generate_password
)

app = FastAPI(title="Крипто-инструменты")

# Настройка шаблонов (папка templates)
templates = Jinja2Templates(directory="templates")

# Модели для запросов (для автоматической валидации)
class AESEncryptRequest(BaseModel):
    key_b64: str
    plaintext: str

class AESDecryptRequest(BaseModel):
    key_b64: str
    iv_b64: str
    ciphertext_b64: str

class HashRequest(BaseModel):
    text: str
    algorithm: str

class Base64Request(BaseModel):
    text: str
    action: str

class PasswordRequest(BaseModel):
    length: int = 16
    use_digits: bool = True
    use_punctuation: bool = True

# ----- Эндпоинты API -----

@app.post("/api/aes/encrypt")
async def api_aes_encrypt(req: AESEncryptRequest):
    try:
        key = base64.b64decode(req.key_b64)
        if len(key) != 32:
            return JSONResponse(status_code=400, content={"error": "Ключ должен быть 32 байта (256 бит)"})
        iv_b64, ct_b64 = aes_encrypt_CBC(key, req.plaintext)
        return {"iv": iv_b64, "ciphertext": ct_b64}
    except Exception as e:
        return JSONResponse(status_code=400, content={"error": str(e)})

@app.post("/api/aes/decrypt")
async def api_aes_decrypt(req: AESDecryptRequest):
    try:
        key = base64.b64decode(req.key_b64)
        if len(key) != 32:
            return JSONResponse(status_code=400, content={"error": "Ключ должен быть 32 байта (256 бит)"})
        plaintext = aes_decrypt_CBC(key, req.iv_b64, req.ciphertext_b64)
        return {"plaintext": plaintext}
    except Exception as e:
        return JSONResponse(status_code=400, content={"error": str(e)})

@app.post("/api/hash")
async def api_hash(req: HashRequest):
    if req.algorithm == "sha256":
        result = sha256_hash(req.text)
    elif req.algorithm == "md5":
        result = md5_hash(req.text)
    else:
        return JSONResponse(status_code=400, content={"error": "Алгоритм должен быть sha256 или md5"})
    return {"algorithm": req.algorithm, "hash": result}

@app.post("/api/base64")
async def api_base64(req: Base64Request):
    try:
        if req.action == "encode":
            result = base64_encode(req.text)
        elif req.action == "decode":
            result = base64_decode(req.text)
        else:
            return JSONResponse(status_code=400, content={"error": "action должно быть encode или decode"})
        return {"action": req.action, "result": result}
    except Exception as e:
        return JSONResponse(status_code=400, content={"error": str(e)})

@app.post("/api/generate-password")
async def api_generate_password(req: PasswordRequest):
    password = generate_password(req.length, req.use_digits, req.use_punctuation)
    return {"password": password}

# Вспомогательный эндпоинт для генерации случайного ключа AES
@app.get("/api/generate-key")
async def generate_key():
    key = get_random_bytes(32)
    return {"key_b64": base64.b64encode(key).decode('utf-8')}

# ----- HTML-интерфейс -----
@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})