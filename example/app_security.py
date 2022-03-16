from enum import Enum

from general import Foo, Bar
from security import Role, Permission, PermissionAction, ApiKey


class AppPermission(Permission, Enum):
    API_KEY_CREATE = 'API_KEY_CREATE', PermissionAction.CREATE, [], ApiKey
    API_KEY_LIST = 'API_KEY_LIST', PermissionAction.LIST, [], ApiKey
    API_KEY_RELATIONSHIP = 'API_KEY_RELATIONSHIP', PermissionAction.RELATIONSHIP, [], ApiKey
    API_KEY_CHILD = 'API_KEY_CHILD', PermissionAction.CHILD, [], ApiKey
    FOO_CREATE = 'FOO_CREATE', PermissionAction.CREATE, [], Foo
    FOO_LIST = 'FOO_LIST', PermissionAction.LIST, [], Foo
    FOO_GET = 'FOO_GET', PermissionAction.GET, [], Foo
    BAR_CREATE = 'BAR_CREATE', PermissionAction.CREATE, [], Bar
    BAR_LIST = 'BAR_LIST', PermissionAction.LIST, [], Bar
    BAR_GET = 'BAR_GET', PermissionAction.GET, [], Bar


class AppRole(Role, Enum):
    ADMIN = 'ADMIN', list(AppPermission), []
    FOO_ADMIN = 'FOO_ADMIN', (AppPermission.FOO_CREATE, AppPermission.FOO_LIST, AppPermission.FOO_GET), []
    BAR_ADMIN = 'BAR_ADMIN', (AppPermission.BAR_CREATE, AppPermission.BAR_LIST, AppPermission.BAR_GET), []


Permission.permissions = list(AppPermission)
Role.roles = list(AppRole)
