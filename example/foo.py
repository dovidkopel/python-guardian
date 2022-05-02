from general import Foo
from security import requires_security
from app_security import AppPermission


@requires_security(permissions=[AppPermission.FOO_GET])
def get_foo():
    return Foo()


@requires_security(permissions=[AppPermission.FOO_CREATE])
def create_foo():
    return Foo()

