from general import Bar
from security import requires_security
from app_security import AppPermission


@requires_security(permissions=[AppPermission.BAR_GET])
def get_bar():
    return Bar()