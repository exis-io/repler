#!/bin/bash

# The following two lines added to the code below are meant to fix a problem
# visible on the website.  They can be removed if all of the example code is
# using ModelObject instead of Model.
#
# from riffle.model import Model as Model
# riffle.Model = Model

cat >main.py <<EOF

import riffle
from riffle import want
from riffle.model import Model
riffle.Model = Model
import lockdown

riffle.SetFabric("$WS_URL")
riffle.SetLogLevelApp()

class Test(riffle.Domain):
    def onJoin(self):
        """Comment completes the method in case EXIS_REPL_CODE does not."""

$EXIS_REPL_CODE

if __name__ == "__main__":
    app = riffle.Domain("$EXIS_REPL_OWNER")
    client = riffle.Domain("client", superdomain=app)
    backend = riffle.Domain("backend", superdomain=app)
    Test("$EXIS_REPL_NAME", superdomain=app).join()

EOF

echo "___BUILDCOMPLETE___"

python -u main.py
