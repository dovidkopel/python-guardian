from __future__ import annotations
from typing import Type, Iterable, Collection, Callable, Dict
from enum import Enum
from uuid import uuid4


class ApiKey:
    def __init__(self,
                 secret_key: str,
                 tenant_id: str = None,
                 roles: Collection[Role] = (),
                 permissions: Collection[Permission] = (),
                 id: str = None):
        self.secret_key = secret_key
        self.tenant_id = tenant_id
        self.roles = list(map(lambda r: r if isinstance(r, Role) else Role.from_str(r), roles))
        self.permissions = list(map(lambda p: p if isinstance(p, Permission) else Permission.from_str(p), permissions))
        self.id = id if id else uuid4().hex

    def __as_dict__(self) -> dict:
        return {
            'id': self.id,
            'secret_key': self.secret_key,
            'tenant_id': self.tenant_id,
            'roles': list(map(lambda r: r.name if r else None, self.roles)),
            'permission': list(map(lambda p: p.name if p else None, self.permissions))
        }


class PermissionAction(Enum):
    CREATE = 0
    LIST = 1
    UPDATE = 2
    DELETE = 3


class Permission:
    permissions = []

    def __init__(self, name: str, action: PermissionAction, grants: Collection[Permission] = [], tpe: Type = None):
        self._name = name
        self._action = action
        self._tpe = tpe
        self._grants = grants

    @staticmethod
    def from_str(_name: str) -> Permission:
        for p in Permission.permissions:
            if p.name == _name:
                return p

    def __repr__(self) -> str:
        return self._name

    def __str__(self) -> str:
        return self._name

    @property
    def name(self):
        return self._name

    def has_permission(self, p: Permission) -> bool:
        if self == p:
            return True
        elif len(self._grants) > 0:
            for pp in self._grants:
                if pp.has_permission(p):
                    return True

        return False


class Role:
    roles = []

    def __init__(self, name: str, permissions: Collection[Permission] = [],
                 roles: Collection[Role] = []):
        self._name = name
        self._permissions = permissions
        self._roles = roles

    @staticmethod
    def from_str(_name: str) -> Role:
        for r in Role.roles:
            if r.name == _name:
                return r

    def __repr__(self) -> str:
        return self._name

    def __str__(self) -> str:
        return self._name

    @property
    def name(self):
        return self._name

    def has_role(self, r: Role) -> bool:
        if self == r:
            return True
        elif len(self._roles) > 0:
            for rr in self._roles:
                if rr.has_role(r):
                    return True

        return False

    def has_permission(self, p: Permission) -> bool:
        if self.name == p.name:
            return True
        elif len(self._permissions) > 0:
            for pp in self._permissions:
                if pp.has_permission(p):
                    return True
        elif len(self._roles) > 0:
            for rr in self._roles:
                if rr.has_permission(p):
                    return True

        return False


class SecurityContext:
    def __init__(self, permissions: Collection[Permission] = [],
                 roles: Collection[Role] = [], details={}):
        self.permissions = permissions
        self.roles = roles
        self.details = details

    @property
    def tenant_id(self) -> str:
        if self.details and 'tenant_id' in self.details.keys():
            return self.details['tenant_id']

    def has_permission(self, permission: Permission) -> bool:
        for p in self.permissions:
            if p.has_permission(permission):
                return True
        for r in self.roles:
            if r.has_permission(permission):
                return True

        return False

    def has_any_permission(self, permissions: Collection[Permission]) -> bool:
        for p in permissions:
            if self.has_permission(p):
                return True

        return False

    def has_role(self, role: Role) -> bool:
        for r in self.roles:
            if r.has_role(role):
                return True

        return False

    def has_any_role(self, roles: Collection[Role]) -> bool:
        for r in roles:
            if self.has_role(r):
                return True

        return False


class SecurityContextHolder:
    context = None

    @staticmethod
    def set_context(_context: SecurityContext):
        SecurityContextHolder.context = _context

    @staticmethod
    def get_context() -> SecurityContext:
        return SecurityContextHolder.context


def establish_security_from_headers(event: dict, lookup: Callable):
    headers = event['headers']
    if 'Authorization' in headers.keys():
        auth = headers['Authorization']
        key = auth.replace('Bearer ', '')
        ak = lookup(key)
        if ak:
            SecurityContextHolder.set_context(
                SecurityContext(ak.permissions, ak.roles, {
                    "secret_key": ak.secret_key,
                    "tenant_id": ak.tenant_id
                })
            )
        else:
            raise SecurityException()
    else:
        raise SecurityException()


class SecurityException(Exception):
    pass


class AuthorizationSecurityException(SecurityException):
    pass


def requires_security(permissions: Collection[Permission] = [],
                      roles: Collection[Role] = []):
    def check_security(func):
        def func_wrapper(*args):
            if SecurityContextHolder.get_context() is None:
                raise SecurityException('No security context found!')
            else:
                for p in permissions:
                    if SecurityContextHolder.get_context().has_permission(p):
                        return func(*args)

                for r in roles:
                    if SecurityContextHolder.get_context().has_role(r):
                        return func(*args)

                raise AuthorizationSecurityException('Unauthorized! Requires either {} or {}'.format(permissions, roles))

        return func_wrapper

    return check_security
