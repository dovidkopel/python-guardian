from api_key import ApiKeyUtils
from bar import get_bar
from foo import get_foo
from security import SecurityContextHolder, SecurityContext, ApiKey, SecurityException, ApiKeySecurityHelper
from app_security import AppPermission, AppRole


error = False
try:
    get_foo()
except SecurityException:
    error = True

assert error is True

SecurityContextHolder.set_context(
    SecurityContext(
        roles=[AppRole.ADMIN],
        details={
            'id': 'john',
            'secret_key': 'foo',
            'name': 'jogn'
        }
    )
)

error = False
try:
    get_foo()
except SecurityException:
    error = True

assert error is False


aku = ApiKeyUtils()
aku.create_api_key(
    ApiKey('foo', 'default', roles=[AppRole.FOO_ADMIN])
)
aku.create_api_key(
    ApiKey('bar', 'default', roles=[AppRole.BAR_ADMIN])
)

SecurityContextHolder.clear_context()
ApiKeySecurityHelper().lookup_key('foo', aku.lookup_api_key)

error = False
try:
    get_foo()
except SecurityException:
    error = True

assert error is False

error = False
try:
    get_bar()
except SecurityException:
    error = True

assert error is True

SecurityContextHolder.clear_context()
ApiKeySecurityHelper().lookup_key('bar', aku.lookup_api_key)

error = False
try:
    get_foo()
except SecurityException:
    error = True

assert error is True

error = False
try:
    get_bar()
except SecurityException:
    error = True

assert error is False

#
# SecurityContextHolder.set_context(
#     SecurityContext(
#         roles=[AppRole.ADMIN],
#         details={
#             'id': 'john',
#             'secret_key': 'foo',
#             'name': 'jogn'
#         }
#     )
# )