import hashlib
import base64
import secrets
import string
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes


# AES_CBC Симметричное шифрование в базовом режиме
def aes_encrypt_CBC(key: bytes, plaintext: str) -> tuple:
    """
    Шифрует строку plaintext алгоритмом AES-256-CBC.
    Возвращает кортеж (iv, ciphertext) в base64 для удобства передачи.
    """
    iv = get_random_bytes(AES.block_size)  # 16 байт
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct_bytes = cipher.encrypt(pad(plaintext.encode('utf-8'), AES.block_size))
    return base64.b64encode(iv).decode('utf-8'), base64.b64encode(ct_bytes).decode('utf-8')



def aes_decrypt_CBC(key: bytes, iv_b64: str, ciphertext_b64: str) -> str:
    """
    Дешифрует данные, зашифрованные AES-256-CBC.
    Принимает ключ, IV и шифротекст в base64.
    Возвращает расшифрованную строку.
    """
    iv = base64.b64decode(iv_b64)
    ct = base64.b64decode(ciphertext_b64)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt.decode('utf-8')




# Хэш-функции SHA-256 и MD5
def sha256_hash(data: str) -> str:
    "Возвращает SHA-256 хэш строки в шестнадцатеричном формате"
    return hashlib.sha256(data.encode('utf-8')).hexdigest()
def md5_hash(data: str) -> str:
    "Возвращает MD5 хэш строки в шестнадцатеричном формате"
    return hashlib.md5(data.encode('utf-8')).hexdigest()


# Base64
def base64_encode(data: str) -> str:
    "Кодирует строку в Base64"
    return base64.b64encode(data.encode('utf-8')).decode('utf-8')

def base64_decode(data_b64: str) -> str:
    "Декодирует строку из Base64"
    return base64.b64decode(data_b64).decode('utf-8')


# Генератор паролей
def generate_password(length: int = 16, use_digits: bool = True, use_punctuation: bool = True) -> str:
    """
    Генерирует криптостойкий пароль заданной длины.
    По умолчанию используются буквы (верхний и нижний регистр), цифры и знаки пунктуации.
    """
    alphabet = string.ascii_letters
    if use_digits:
        alphabet += string.digits
    if use_punctuation:
        alphabet += string.punctuation

    # secrets.choice — криптографически безопасный выбор
    password = ''.join(secrets.choice(alphabet) for _ in range(length))
    return password





# тестирование
if __name__ == "__main__":
    print("Проверка работы AES")
    # создаёт случайный ключ блиной 32 байта
    key = get_random_bytes(32)
    print(base64.b64encode(key).decode())
    original_text = "Привет, мир!"
    print(original_text)

    print('-'*20+'Шифротекст'+'-'*20)
    iv_b64, ciphertext_b64 = aes_encrypt_CBC(key, original_text)
    print(iv_b64,ciphertext_b64)

    print('-'*20+'Дешифровка'+'-'*20)
    decrypted_text = aes_decrypt_CBC(key, iv_b64, ciphertext_b64)
    print( decrypted_text)
    print('-'*60)

    print('Проверка работы Хэш-функции:')
    print(f"SHA-256: {sha256_hash('ПРОВЕРКА')}")
    print(f"SHA-256: {sha256_hash('ПРОВЕРКАА')}")
    print(f"MD5: {md5_hash('ПРОВЕРКА')}")
    print(f"MD5: {md5_hash('ПРОВЕРКАА')}")
    print('-'*60)
    print('Генерация пороля')
    print( generate_password())

    print("Пароль 8 символов (только буквы и цифры):", generate_password(8, use_punctuation=False))
    print("Пароль 20 символов (только буквы):", generate_password(20, use_digits=False, use_punctuation=False))
    print("Пароль 12 символов (буквы и знаки, без цифр):",generate_password(12, use_digits=False, use_punctuation=True))

    print('-'*60)
    proverka=base64_encode(original_text)
    print('Перевод в Base64 :', proverka)

    print('Из Base64 :',base64_decode(proverka))
