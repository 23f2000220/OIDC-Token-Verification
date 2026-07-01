from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import jwt
from jwt.exceptions import ExpiredSignatureError, InvalidAudienceError, InvalidIssuerError, InvalidTokenError

from jwt.algorithms import get_default_algorithms

import cryptography
# print("CARTO",cryptography.__version__)

# print("DEF ALGOS:",get_default_algorithms().keys())


# print("FILE:",jwt.__file__)
# print("VERSION:",jwt.__version__)



app = FastAPI()

ISSUER = "https://idp.exam.local"
AUDIENCE = "tds-t5wq60qb.apps.exam.local"
PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2okOHspNjgA+2rTLbeuY
cxiP/hG8C6Sb9iwg3yiLAA4HCnpITcbWCSelbvbYGuc3EbNy4xFyf5Cbj5DHJMID
EkryOgyd2giIIIBOUBj8S63uGcnRpOBh9NFatfNwheKuzsPuVNldu6A9cNteNpXc
WyJjG2axVfmq7i6SuKr1JoWYG7xTTAvKPujSl4OtsQfO3h5NepzdfXpr28oNnzfW
ed+zclR6BcmNNo/WVfJ4xyCLSf0BCOgdTgW6PdaChd1l9VDetJZVEgC5tkyvXsfI
SI6iyrYbKR0NEBSqq4XkadEjsCs4F1RncsS4LlgniT7GlkL9Mce3b0wGLs9/7ZIX
dQIDAQAB
-----END PUBLIC KEY-----"""

class TokenBody(BaseModel):
    token: str

@app.post("/verify")
def verify_token(body: TokenBody):
    
    try:
        print("HEADER",jwt.get_unverified_header(body.token))
        payload = jwt.decode(
            body.token,
            PUBLIC_KEY,
            algorithms=["RS256"],
            issuer=ISSUER,
            audience=AUDIENCE,
            options={"require": ["exp", "iss", "aud"]},
        )
        return {
            "valid": True,
            "email": payload.get("email"),
            "sub": payload.get("sub"),
            "aud": payload.get("aud"),
        }
    # except (ExpiredSignatureError, InvalidAudienceError, InvalidIssuerError, InvalidTokenError):
    #     return JSONResponse(status_code=401, content={"valid": False})
    except Exception as e:
        print("Exception:",type(e).__name__, e)
        return JSONResponse(
            status_code=401,
            content={"valid": False},
        )
    
