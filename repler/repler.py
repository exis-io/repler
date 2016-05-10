#!/usr/bin/python2

import datetime
import os
import re
import sys
import time

import docker

from autobahn.wamp.types import RegisterOptions
from twisted.internet import reactor
from twisted.internet.defer import inlineCallbacks, returnValue
from twisted.internet.threads import deferToThread
from pprint import pprint

from pyriffle import FabricSession

TLD = "xs.demo"

MEMORY_LIMIT = "300m"

# Let their code run for up to 15 minutes.
#
# Note: although we allow the process to persist for a long time, we use ulimit
# to enforce a strict CPU usage limit.  In this way, we can allow friendly code
# to persist while quickly killing spin-loops, fork bombs, etc.
MAX_RUN_TIME = 15 * 60

# Maximum number of containers to run concurrently.
#
# When we hit the limit, new requests will fail with a friendly message.
MAX_CONTAINERS = 24

# Limits to apply on containers through the ulimits host configuration option.
# With the CPU limit, the process will be killed after the set number of CPU
# seconds.
ULIMITS = [
    {"Name": "nofile", "Soft": 32, "Hard": 32},
    {"Name": "cpu", "Soft": 5, "Hard": 5}
]

# If true, containers run under the same domain as the caller instead of their
# own domains.
USE_CALLER_DOMAIN = False

TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S"


class AppSession(FabricSession):
    def __init__(self, config):
        super(AppSession, self).__init__(config=config)
        self.args = config.extra
        self.docker = docker.Client(base_url=self.args['docker'],
                version="auto")

        # map container name -> container ID
        self.containers = dict()

    @inlineCallbacks
    def onJoin(self, details):
        super(AppSession, self).onJoin(details)
        yield self.removeOldContainers()

        # We have to pass this option for methods that should return
        # progressive results.
        options = RegisterOptions(details_arg='details')

        yield self.register(self.startContainer, "startContainer#details",
                options=options)
        yield self.register(self.stopContainer, "stopContainer#details")

    @inlineCallbacks
    def startContainer(self, xdetails, name, language, code, details=None):
        caller = xdetails['caller']

        on_progress = None
        if details is not None:
            on_progress = details.progress

        image = "repl-{}".format(language)

        # Full name of container includes owner.
        fullname = caller + "." + name

        host_config = self.docker.create_host_config(
            extra_hosts={'node': '172.17.0.1'},
            mem_limit=MEMORY_LIMIT,
            ulimits=ULIMITS)

        environ = {
            'WS_URL': self.node,
            'EXIS_REPL_CODE': code,
            'EXIS_REPL_NAME': name,
            'EXIS_REPL_OWNER': caller
        }

        # This is the domain we tell the user code to connect under.
        if USE_CALLER_DOMAIN:
            environ['DOMAIN'] = caller
        else:
            environ['DOMAIN'] = fullname

        if fullname in self.containers:
            oldcid = self.containers[fullname]['Id']
            try:
                del self.containers[fullname]
                self.docker.remove_container(container=oldcid, force=True)
            except docker.errors.APIError as error:
                print("Warning: {}".format(error.explanation))

        if len(self.containers) >= MAX_CONTAINERS:
            raise Exception("The system is currently experiencing heavy load. "
                            "Please try again later.")

        try:
            result = self.docker.create_container(image=image,
                    host_config=host_config, environment=environ)
        except docker.errors.APIError as error:
            raise Exception(error.explanation)

        cid = result['Id']

        self.containers[fullname] = {
            'Id': cid,
            'Created': time.time()
        }

        try:
            self.docker.start(container=cid)
        except docker.errors.APIError as error:
            raise Exception(error.explanation)

        print("[{}] Started container {} with domain {} from image {}".format(
            datetime.datetime.now().strftime(TIMESTAMP_FORMAT),
            cid, environ['DOMAIN'], image))

        # Schedule removal of the container.
        reactor.callLater(MAX_RUN_TIME, self.removeContainer, fullname, cid)

        output = yield deferToThread(self.watchContainer, cid, on_progress)
        returnValue(output)

    def stopContainer(self, xdetails, name):
        caller = xdetails['caller']

        # Full name of container includes owner.
        fullname = caller + "." + name

        if fullname in self.containers:
            cid = self.containers[fullname]['Id']
            self.removeContainer(fullname, cid)

    #
    # Private methods
    #

    def removeContainer(self, cname, cid):
        """
        Stop and remove a REPL container.

        This method takes the container name and ID so that it can verify that
        the container has not already been replaced with a newer version (same
        name, different ID).
        """
        if cname in self.containers and self.containers[cname]['Id'] == cid:
            try:
                del self.containers[cname]
                self.docker.remove_container(container=cid, force=True)
            except docker.errors.APIError as error:
                print("Warning: {}".format(error.explanation))

    def watchContainer(self, cid, on_progress):
        output = list()

        messages = self.docker.attach(container=cid, stream=True, logs=True)
        for msg in messages:
            lines = msg.rstrip().split("\n")
            if on_progress is None:
                output.extend(lines)
            else:
                for line in lines:
                    on_progress(line)

        return output

    @inlineCallbacks
    def removeOldContainers(self):
        repl_re = re.compile("repl-[a-z]+")

        containers = yield deferToThread(self.docker.containers, all=True)
        for container in containers:
            if repl_re.match(container['Image']) is not None:
                yield deferToThread(self.docker.remove_container,
                        container=container['Id'], force=True)


def main():
    authid = os.environ.get("AUTHID", None)
    domain = os.environ.get("DOMAIN", "{}.repler".format(TLD))
    ws_url = os.environ.get("WS_URL", "ws://172.17.42.1:8000/ws")
    docker = os.environ.get("DOCKER", "tcp://127.0.0.1:5555")

    args = dict()
    args['authid'] = authid
    args['docker'] = docker

    AppSession.start(unicode(ws_url), unicode(domain),
            extra=args, start_reactor=True, retry=True)


if __name__ == "__main__":
    main()
