from __future__ import annotations

from abc import abstractmethod, ABC
from typing import Type, Iterable, Collection, Callable, Dict, TypeVar, Generic
from enum import Enum
from uuid import uuid4


from logging import getLogger


logger = getLogger('python_guardian')


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
    RELATIONSHIP = 4
    CHILD = 5
    GET = 6


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
        self.temp_permissions = {}
        self.temp_roles = {}

    @property
    def name(self) -> str:
        if self.details and 'name' in self.details.keys():
            return self.details['name']

    @property
    def tenant_id(self) -> str:
        if self.details and 'tenant_id' in self.details.keys():
            return self.details['tenant_id']

    def has_permission(self, permission: Permission) -> bool:
        logger.debug('Looking at permissions: {}'.format(self.permissions))
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

    def add_temp_permission(self, id: str, p: Permission) -> bool:
        if p not in self.permissions and '{}:{}'.format(id, p.name) not in self.temp_permissions.keys():
            self.temp_permissions['{}:{}'.format(id, p.name)] = p
            self.permissions.append(p)
            logger.debug('Permissions now: {}'.format(self.permissions))
            return True
        else:
            return False

    def remove_temp_permission(self, id: str, r: Permission):
        if '{}:{}'.format(id, r.name) in self.temp_permissions.keys():
            del self.temp_permissions['{}:{}'.format(id, r.name)]
            self.permissions.remove(r)
            return True
        else:
            return False

    def add_temp_role(self, id: str, r: Role) -> bool:
        if r not in self.roles and '{}:{}'.format(id, r.name) not in self.temp_roles.keys():
            self.temp_roles['{}:{}'.format(id, r.name)] = r
            self.roles.append(r)
            return True
        else:
            return False

    def remove_temp_role(self, id: str, r: Role):
        if '{}:{}'.format(id, r.name) in self.temp_permissions.keys():
            del self.temp_roles['{}:{}'.format(id, r.name)]
            self.roles.remove(r)
            return True
        else:
            return False


class SecurityContextHolder:
    context = None

    @staticmethod
    def set_context(_context: SecurityContext):
        SecurityContextHolder.context = _context

    @staticmethod
    def get_context() -> SecurityContext:
        return SecurityContextHolder.context


T = TypeVar('T')
S = TypeVar('S')


class GenericSecurityHelper(Generic[T, S], ABC):
    @abstractmethod
    def lookup_key(self, key: S, lookup: Callable[[S], T], ):
        pass

    def establish_security_from_headers(self, event: dict, lookup: Callable[[S], T]):
        headers = event['headers']
        if 'Authorization' in headers.keys():
            auth = headers['Authorization']
            key = auth.replace('Bearer ', '')
            return self.lookup_key(key, lookup)
        elif 'token' in event['queryStringParameters']:
            return self.lookup_key(event['queryStringParameters']['token'], lookup)
        else:
            raise SecurityException()


class ApiKeySecurityHelper(GenericSecurityHelper[ApiKey, str]):
    def lookup_key(self, key: str, lookup: Callable[[str], ApiKey]):
        ak = lookup(key)
        if ak:
            SecurityContextHolder.set_context(
                SecurityContext(ak.permissions, ak.roles, {
                    "name": ak.secret_key,
                    "secret_key": ak.secret_key,
                    "tenant_id": ak.tenant_id
                })
            )
        else:
            raise SecurityException()


class SecurityException(Exception):
    pass


class AuthorizationSecurityException(SecurityException):
    pass


def security_check(func: Callable, permissions: Collection[Permission] = [],
                   roles: Collection[Role] = [], *args, **kwargs):
    if SecurityContextHolder.get_context() is None:
        raise SecurityException('No security context found!')
    else:
        for p in permissions:
            if SecurityContextHolder.get_context().has_permission(p):
                return func(*args, **kwargs)

        for r in roles:
            if SecurityContextHolder.get_context().has_role(r):
                return func(args, **kwargs)

        raise AuthorizationSecurityException('Unauthorized! Requires either {} or {}'.format(permissions, roles))


def requires_security(permissions: Collection[Permission] = [],
                      roles: Collection[Role] = [],
                      grant_permissions: Collection[Permission] = [],
                      grant_roles: Collection[Role] = []):
    def check_security(func):
        def func_wrapper(*args, **kwargs):
            if SecurityContextHolder.get_context() is None:
                raise SecurityException('No security context found!')
            else:
                retval = None  # Hold the return value
                called = False  # Not everything has a return value

                # Grants
                id = uuid4().hex  # Used to isolate grant to a function call
                if len(grant_permissions) > 0:
                    for gp in grant_permissions:
                        gg = SecurityContextHolder.get_context().add_temp_permission(id, gp)
                        logger.debug('Granting permission "{}", {}'.format(gp, gg))

                if len(grant_roles) > 0:
                    for gr in grant_roles:
                        gg = SecurityContextHolder.get_context().add_temp_role(id, gr)
                        logger.debug('Granting role "{}", {}'.format(gr, gg))

                for p in permissions:
                    if SecurityContextHolder.get_context().has_permission(p):
                        retval = func(*args, **kwargs)
                        called = True
                        break

                if called is False:  # Only if it hasn't been called yet
                    for r in roles:
                        if SecurityContextHolder.get_context().has_role(r):
                            retval = func(*args, **kwargs)
                            called = True
                            break

                if len(grant_permissions) > 0:
                    for gp in grant_permissions:
                        logger.debug('Revoking permission "{}", {}'.format(gp, SecurityContextHolder.get_context().remove_temp_permission(id, gp)))

                if len(grant_roles) > 0:
                    for gr in grant_roles:
                        logger.debug('Revoking role "{}", {}'.format(gr, SecurityContextHolder.get_context().remove_temp_role(id, gr)))

                if retval is not None:
                    return retval
                elif called is True:
                    return

                raise AuthorizationSecurityException('Unauthorized! Requires either {} or {}'.format(permissions, roles))

        return func_wrapper

    return check_security
