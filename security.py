from datetime import UTC, datetime, timedelta

import jwt
from pwdlib import PasswordHash

from settings import settings

password_hash = PasswordHash.recommended()

# 用于防止计时攻击的虚拟哈希
DUMMY_HASH = password_hash.hash("dummy-password-for-timing-attack-prevention")

ACCESS_TOKEN_ALGORITHM = "HS256"  # 访问令牌使用的算法
ACCESS_TOKEN_EXPIRATION_TIME_IN_MINUTES = 10  # 令牌过期时间，单位为分钟
REFRESH_TOKEN_EXPIRATION_TIME_IN_DAYS = 7  # 刷新令牌过期时间，单位为天
ACCESS_TOKEN_SECRET = settings.JWT_SECRET_KEY


# 密码生成
def hash_password(plain_password: str) -> str:
    return password_hash.hash(plain_password)


# 密码验证
def verify_password(plain_password: str, hashed: str) -> bool:
    return password_hash.verify(plain_password, hashed)


# 生成访问令牌
def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    to_encode = data.copy()
    now = datetime.now(UTC)
    expire = now + (
        expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRATION_TIME_IN_MINUTES)
    )
    to_encode.update({"exp": expire, "iat": now, "type": "access"})
    return jwt.encode(to_encode, ACCESS_TOKEN_SECRET, algorithm=ACCESS_TOKEN_ALGORITHM)


# 生成刷新令牌
def create_refresh_token(data: dict, expires_delta: timedelta | None = None) -> str:
    to_encode = data.copy()
    now = datetime.now(UTC)
    expire = now + (
        expires_delta or timedelta(days=REFRESH_TOKEN_EXPIRATION_TIME_IN_DAYS)
    )
    to_encode.update({"exp": expire, "iat": now, "type": "refresh"})
    return jwt.encode(to_encode, ACCESS_TOKEN_SECRET, algorithm=ACCESS_TOKEN_ALGORITHM)


# 解码访问令牌
def decode_token(token: str) -> dict | None:
    try:
        payload = jwt.decode(
            token, ACCESS_TOKEN_SECRET, algorithms=[ACCESS_TOKEN_ALGORITHM]
        )
        return payload
    except jwt.PyJWTError:
        return None
