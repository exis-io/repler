#!/bin/bash

cat >main.js <<EOF
var riffle = require('jsriffle');

riffle.setFabric("$WS_URL");

var app = riffle.Domain("$EXIS_REPL_OWNER");
var backend = app.subdomain("backend");
var client = app.subdomain("client");
var session = app.subdomain("$EXIS_REPL_NAME");

session.onJoin = function() {
    $EXIS_REPL_CODE
};

session.join()
EOF

echo "___BUILDCOMPLETE___"

nodejs main.js
