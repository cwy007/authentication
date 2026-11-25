from pwdlib import PasswordHash

password_hash = PasswordHash.recommended()

# 用于防止计时攻击的虚拟哈希
DUMMY_HASH = password_hash.hash("dummy-password-for-timing-attack-prevention")


# 密码生成
def hash_password(plain_password: str) -> str:
    return password_hash.hash(plain_password)


# 密码验证
def verify_password(plain_password: str, hashed: str) -> bool:
    return password_hash.verify(plain_password, hashed)
