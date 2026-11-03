"""ZAP hook for the API scan: send a bearer token with every request.

Passing "Bearer <token>" through ZAP's -z option does not work, because the option string is split on
spaces. A hook sets the same rule through ZAP's API instead. The token comes from the environment and
is never written to a file.
"""
import os


def zap_started(zap, target):
    token = os.environ["ZAP_AUTH_TOKEN"]
    zap.replacer.add_rule(
        description="bearer-auth",
        enabled="true",
        matchtype="REQ_HEADER",
        matchregex="false",
        matchstring="Authorization",
        replacement="Bearer " + token,
        initiators="",
    )
    print("auth hook: Authorization header rule added (token not shown)")
