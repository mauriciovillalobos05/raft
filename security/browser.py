"""Observe browser TLS after asyncio completes its handshake, before HTTP data."""
from uvicorn.protocols.http.h11_impl import H11Protocol
from security.transport import EVIDENCE, LOG, TransportError, observe_socket, enforce


class EvidenceHTTPProtocol(H11Protocol):
    def connection_made(self, transport):
        self._transport_allowed = False
        super().connection_made(transport)
        try:
            connection = transport.get_extra_info('ssl_object')
            if connection is None:
                raise TransportError('HTTPS transport required')
            # Browser clients authenticate later with Basic/session credentials.
            # Do not misrepresent an unauthenticated TLS peer as an HTTP user.
            record = observe_socket(connection, 'browser-https', 'accepted',
                                    'https-gateway', 'unauthenticated-https-peer')
            enforce(record)
            EVIDENCE.add(dict(record, peer_agreed=False, evidence_scope='server-observed'), 'accepted')
            self._transport_allowed = True
        except TransportError:
            LOG.warning('Rejected HTTPS connection without valid classical TLS evidence')
            transport.close()

    def data_received(self, data):
        if self._transport_allowed:
            super().data_received(data)
