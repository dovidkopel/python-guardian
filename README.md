# Python Guardian

This library is very much influenced by the Java framework Spring Security.
This is obviously a lightweight library that aims to add a security layer without too much work.

The library does not care about where your users are stored. 
The primary `SecurityContextHolder` holds the relevant security data.
The library has a simple `lookupKey(key: ApiKey, lookup: Callable)` function

The two main security constructs are:
* Role - A named role that should emulate a business role or function. A role may have child roles and permissions. Try to make roles very simple and specific. If you have a job function that is essentially a hybrid of several roles that is a good use case for inherited roles or permissions. Here any child roles declared are contained within. This is useful for managers or executives. 
* Permission - A name permission should be a specific action against an entity. If you want to use simple entities with CRUD functionality a permission might be `DOCUMENT_CREATE`. In this case the `Document` is an Entity, and the operation is `CREATE`. Just like roles, permissions can inherit as well.

