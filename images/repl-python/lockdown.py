# Import this module to block access to system modules in the blacklist.
# The effect of importing this module is that future attempts to import
# blacklisted modules will fail with an ImportError.
#
# Example:
# import os <- No error!
# import lockdown
# import sys <- Error!

import sys

BLACKLIST = [
    "multiprocessing",
    "os",
    "subprocess",
    "sys",
    "thread",
    "threading"
]

for mod in BLACKLIST:
    sys.modules[mod] = None

del sys
