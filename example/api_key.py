import json
import os
from typing import Callable

from security import requires_security, ApiKey, GenericSecurityHelper, SecurityContextHolder, SecurityContext, \
    SecurityException
from app_security import AppPermission, AppRole


class ApiKeyUtils:
    def __init__(self):
        if not os.path.isdir('keys'):
            os.mkdir('keys')

    @requires_security(permissions=[AppPermission.API_KEY_CREATE])
    def create_api_key(self, key: ApiKey):
        with open('keys/{}.json'.format(key.secret_key), 'w') as f:
            f.write(json.dumps(key.__as_dict__()))
            f.close()

    def lookup_api_key(self, secret: str) -> ApiKey:
        if os.path.isfile('keys/{}.json'.format(secret)):
            with open('keys/{}.json'.format(secret)) as f:
                d = json.loads(f.read())
                return ApiKey.__from_dict__(d)
