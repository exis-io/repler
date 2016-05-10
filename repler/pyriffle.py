'''
Python implementation of Riffle client side libraries.

Fork of wamp. Used for convenience, high level operations, and more.
'''

'''
Wamp utility methods.
'''

import base64
import json
import six
import os
import urlparse

from OpenSSL import crypto
from autobahn.twisted import wamp, websocket
from autobahn.twisted.wamp import ApplicationSession, ApplicationRunner
from autobahn.wamp.types import RegisterOptions, SubscribeOptions, CallOptions, PublishOptions, ComponentConfig
from twisted.internet import reactor
from twisted.internet.defer import inlineCallbacks, returnValue, Deferred
from twisted.internet.protocol import ReconnectingClientFactory
from twisted.internet.ssl import ClientContextFactory

import rcrypto


# Try pulling in credentials from environment variables.
# TOKEN is a random string received from the auth appliance.
# KEY is the path to an RSA private key.
EXIS_TOKEN = os.environ.get("EXIS_TOKEN", None)
EXIS_KEY   = os.environ.get("EXIS_KEY", None)


# Options related to freezing/thawing sessions.
# These are sent with the session join request.
EXIS_GUARDIAN_DOMAIN = os.environ.get("EXIS_GUARDIAN_DOMAIN", None)
EXIS_GUARDIAN_ID = os.environ.get("EXIS_GUARDIAN_ID", None)
EXIS_SESSION_ID = os.environ.get("EXIS_SESSION_ID", None)
EXIS_RESUME_FROM = os.environ.get("EXIS_RESUME_FROM", None)


def getPrivateKey(source):
    """
    Try loading private key from file or PEM-encoded string.
    """
    # Source is already a key?
    if isinstance(source, crypto.PKey):
        return source

    if os.path.exists(source):
        try:
            key = rcrypto.load_key_from_file(source)
            return key
        except OSError as error:
            # Probably means the key does not exist.
            pass

    else:
        try:
            key = crypto.load_privatekey(crypto.FILETYPE_PEM, source)
            return key
        except Exception as error:
            print("exception loading key: {}".format(error))
            pass

    return None


# pylint: disable=inconsistent-mro
class FabricClientFactory(websocket.WampWebSocketClientFactory, ReconnectingClientFactory):
    # factor and jitter are two variables that control the exponential backoff.
    # The default values in ReconnectingClientFactory seem reasonable.
    initialDelay = 1
    maxDelay = 600

    def clientConnectionFailed(self, connector, reason):
        ReconnectingClientFactory.clientConnectionFailed(self, connector, reason)

    def clientConnectionLost(self, connector, reason):
        ReconnectingClientFactory.clientConnectionLost(self, connector, reason)


class FabricSessionFactory(wamp.ApplicationSessionFactory):
    def __init__(self, config, deferred=None):
        super(FabricSessionFactory, self).__init__(config)
        self.dee = deferred

    def __call__(self, *args, **kwargs):
        sess = super(FabricSessionFactory, self).__call__(*args, **kwargs)
        sess.dee = self.dee
        return sess


class FabricSession(ApplicationSession):

    """ Temporary base class for crossbar implementation """

    def __init__(self, config=None):
        ApplicationSession.__init__(self, config=config)

        self.node = config.extra['node']

        if 'domain' in config.extra:
            self.domain = config.extra['domain']
        else:
            # TODO deprecate pdid
            self.domain = config.extra['pdid']

        self.pdid = config.extra['pdid']
        self.authid = config.extra.get('authid', self.pdid)

        # Need some idea of top level domain so we know which bouncer to call
        self.topLevelDomain = config.extra.get('topLevelDomain', 'xs.demo')

        # extra overrides the environment variable
        self.token = config.extra.get('token', None)
        if self.token is None:
            self.token = EXIS_TOKEN

        keySource = config.extra.get('key', None)
        if keySource is None:
            keySource = EXIS_KEY

        if keySource is None:
            self.key = None
        else:
            self.key = getPrivateKey(keySource)

        # Set by the start class method.
        self.dee = None


    @classmethod
    def start(klass, address, pdid, realm='crossbardemo', extra=None,
            start_reactor=False, debug=False, retry=True):
        '''
        Creates a new instance of this session and attaches it to the router
        at the given address and realm. The pdid is set manually now since we trust
        clients. Excessively.

        For now the realm is automatically set as a demo realm since we are not
        using multiple realms.

        Optional values that can be passed through extra:
        authid: ID to use for authentication (login or key checking).  This can
            be used when setting pdid to be a subdomain of one's domain.  For
            example, the user "pd.damouse" can connect to the fabric as
            pdid="pd.damouse.aardvark" by supplying his credentials for
            authid="pd.damouse".
        '''
        # Configuration
        if extra is None:
            extra = {}
        else:
            extra = dict.copy(extra)
        extra['node'] = address
        extra['pdid'] = u'' + pdid

        dee = Deferred()

        component_config = ComponentConfig(realm=pdid, extra=extra)
        session_factory = FabricSessionFactory(config=component_config, deferred=dee)
        session_factory.session = klass

        transport_factory = FabricClientFactory(session_factory)
        if not retry:
            transport_factory.maxRetries = 0

        uri = urlparse.urlparse(address)
        transport_factory.host = uri.hostname
        transport_factory.port = uri.port
        transport_factory.isSecure = (uri.scheme == 'wss')

        context_factory = ClientContextFactory()

        websocket.connectWS(transport_factory, context_factory)

        if start_reactor:
            reactor.run()

        return dee

    def join(self, realm):
        authmethods = []
        if self.key is not None:
            authmethods.append(u'signature')
        if self.token is not None:
            authmethods.append(u'token')

        extra = dict()
        if EXIS_GUARDIAN_DOMAIN is not None:
            extra['guardianDomain'] = EXIS_GUARDIAN_DOMAIN
        if EXIS_GUARDIAN_ID is not None:
            extra['guardianID'] = EXIS_GUARDIAN_ID
        if EXIS_SESSION_ID is not None:
            extra['sessionID'] = EXIS_SESSION_ID
        if EXIS_RESUME_FROM is not None:
            extra['resumeFrom'] = EXIS_RESUME_FROM

        super(FabricSession, self).join(realm, authmethods=authmethods,
                authid=self.authid, authextra=extra)

    def leave(self):
        # Do not retry if explicitly asked to leave.
        self._transport.factory.maxRetries = 0
        super(FabricSession, self).leave()

    @inlineCallbacks
    def onJoin(self, details):
        #out.info(str(self.__class__.__name__) + ' crossbar session connected')
        yield

        # Reset exponential backoff timer after a successful connection.
        self._transport.factory.resetDelay()

        # Inform whoever created us that the session has finished connecting.
        # Useful in situations where you need to fire off a single call and not a
        # full wamplet
        if self.dee is not None:
            yield self.dee.callback(self)

    def onChallenge(self, details):
        if details.method == "signature":
            if self.key is None:
                return u''
            nonce = details.extra['challenge']
            hmethod = str(details.extra['hash'])
            sig = rcrypto.sign_message(self.key, nonce, hmethod)
            sig = base64.b64encode(sig)
            return unicode(sig)

        elif details.method == "token":
            if self.token is None:
                return u''
            else:
                return unicode(self.token)

        else:
            return u''

    @inlineCallbacks
    def addBouncerPermissions(self, agent, actions):
        """
            Adds permissions into bouncer so other domains can contact endpoints of this appliance
                agent: the agent who can call this appliance,
                actions: a list of actions that can be called (need to be converted to full endpoints)
        """
        # Convert actions to full endpoints
        perms = ["{}/{}".format(self.pdid, action) for action in actions]
        bouncerEndpoint = "{}.Bouncer/setPerm".format(self.topLevelDomain)
        if agent is not None:
            agent = str(agent)
        ret = yield self.absCall(bouncerEndpoint, agent, perms)

        returnValue(ret)

    # def onDisconnect(self):
    # print "disconnected"
    #     reactor.stop()

    ###################################################
    # Overridden CX interaction methods
    ###################################################

    '''
    Note: this first set of methods have all the REAL implemnetion of caller identification:
    the caller's information is always passed along for every call. In the crossbar way of doing
    things, however, whats passed along is a session id and not our pdid.

    The second set of methods is temporary in that it manually passes the
    current sessions' pdid. This is not secure, but will have to do for now in the
    absence of crossbar router changes.
    '''

    # def publish(self, topic, *args, **kwargs):
    #     kwargs['options'] = PublishOptions(disclose_me=True)
    #     return ApplicationSession.publish(self, topic, *args, **kwargs)

    # def subscribe(self, handler, topic=None, options=None):
    #     options = SubscribeOptions(details_arg='details')
    #     return ApplicationSession.subscribe(self, handler, topic=topic, options=options)

    # def call(self, procedure, *args, **kwargs):
    #     kwargs['options'] = CallOptions(disclose_me=True)
    #     return ApplicationSession.call(self, procedure, *args, **kwargs)

    # def register(self, endpoint, procedure=None, options=None):
    #     options = RegisterOptions(details_arg='details')
    #     return ApplicationSession.register(self, endpoint, procedure=procedure, options=options)

    def publish(self, topic, *args, **kwargs):
        # kwargs['options'] = PublishOptions(disclose_me=True)
        topic = _prepend(self.pdid, topic)
        #out.info('riff: (%s) publish (%s)' % (self.pdid, topic,))
        return ApplicationSession.publish(self, topic, *args, **kwargs)

    def subscribe(self, handler, topic=None, options=None):
        topic = _prepend(self.pdid, topic)
        #out.info('riff: (%s) subscribe (%s)' % (self.pdid, topic,))
        return ApplicationSession.subscribe(self, handler, topic=topic, options=options)

    def call(self, procedure, *args, **kwargs):
        # kwargs['options'] = CallOptions(disclose_me=True)
        procedure = _prepend(self.pdid, procedure)
        #out.info('riff: (%s) calling (%s)' % (self.pdid, procedure,))
        return ApplicationSession.call(self, procedure, *args, **kwargs)

    def register(self, endpoint, procedure=None, options=None):
        # options = RegisterOptions(details_arg='session')
        procedure = _prepend(self.pdid, procedure)
        #out.info('riff: (%s) register (%s)' % (self.pdid, procedure,))
        return ApplicationSession.register(self, endpoint, procedure=procedure, options=options)

    ###################################################
    # Absolute (not relative to your PDID)
    # In other words, all these methods require a permission check
    ###################################################
    def absPublish(self, topic, *args, **kwargs):
        #out.info('riff: (%s) publish (%s)' % (self.pdid, topic,))
        return ApplicationSession.publish(self, u'' + topic, *args, **kwargs)

    def absSubscribe(self, handler, topic=None, options=None):
        #out.info('riff: (%s) subscribe (%s)' % (self.pdid, topic,))
        return ApplicationSession.subscribe(self, handler, topic=u'' + topic, options=options)

    def absCall(self, procedure, *args, **kwargs):
        #out.info('riff: (%s) calling (%s)' % (self.pdid, procedure,))
        return ApplicationSession.call(self, u'' + procedure, *args, **kwargs)

    def absRegister(self, endpoint, procedure=None, options=None):
        #out.info('riff: (%s) registering (%s)' % (self.pdid, procedure,))
        return ApplicationSession.register(self, endpoint, procedure=u'' + procedure, options=options)


def _prepend(pdid, topic):
    '''
    In order to make subscription and execution code cleaner, this method automatically
    injects this classes pdid to the start of any publish or register call.

    The topic is also converted to a unicode string. An underscore is inserted to the
    start of every topic. No consideration is given to 'valid' topics-- thats on you.
    '''
    return u'' + pdid + '/' + topic
