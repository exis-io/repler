#!/bin/bash

cat >./main/main.swift <<EOF
import Riffle

Riffle.SetFabric("$WS_URL")

let app = Riffle.Domain(name: "$EXIS_REPL_OWNER")
let client = Riffle.Domain(name: "client", superdomain: app)
let backend = Riffle.Domain(name: "backend", superdomain: app)

func print(msg: String) {
    Riffle.ApplicationLog(msg)
}

class Session: Riffle.Domain, Riffle.Delegate  {
    override func onJoin() {
        $EXIS_REPL_CODE
    }
}

Session(name: "$EXIS_REPL_NAME", superdomain: app).join()
EOF

init-app.sh &>init.log

echo "___BUILDCOMPLETE___"

main
