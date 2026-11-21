import assert from 'assert';
import { Base64 } from 'js-base64';

import parsers from '../../core/proxy-utils/parsers';
import ClashMetaProducer from '../../core/proxy-utils/producers/clashmeta';

function makeGostSocksUri({
    username = 'demo-user',
    password = 'demo-password',
    server = '203.0.113.10',
    port = 8080,
    remarks = 'SOCKS GOST TEST',
    gost = {},
} = {}) {
    const payload = Base64.encode(
        `${encodeURIComponent(username)}:${encodeURIComponent(
            password,
        )}@${server}:${port}`,
    );

    const gostPayload = Base64.encode(JSON.stringify(gost));

    return (
        `socks://${payload}` +
        `?remarks=${encodeURIComponent(remarks)}` +
        `&gost=${encodeURIComponent(gostPayload)}`
    );
}

function parseProxy(uri) {
    const parser = parsers.find((item) => item.test(uri));

    assert(parser);

    return parser.parse(uri);
}

describe('SOCKS GOST URI parser', () => {
    it('parses SOCKS5 over WebSocket GOST metadata for Mihomo', () => {
        const username = 'demo:user';
        const password = 'demo-password';

        const server = '203.0.113.10';
        const port = 8080;

        const wsHost = 'ws.example.invalid';
        const wsPath = '/gost';

        const payload = Base64.encode(
            `${encodeURIComponent(username)}:${encodeURIComponent(
                password,
            )}@${server}:${port}`,
        );

        const gost = Base64.encode(
            JSON.stringify({
                path: wsPath,
                host: wsHost,
                route: 'ws',
            }),
        );

        const uri =
            `socks://${payload}` +
            `?remarks=${encodeURIComponent('SOCKS GOST WS TEST')}` +
            `&gost=${encodeURIComponent(gost)}`;

        const parser = parsers.find((item) => item.test(uri));

        assert(parser);

        const proxy = parser.parse(uri);

        assert.strictEqual(proxy.name, 'SOCKS GOST WS TEST');
        assert.strictEqual(proxy.type, 'socks5');

        assert.strictEqual(proxy.server, server);
        assert.strictEqual(proxy.port, port);

        assert.strictEqual(proxy.username, username);
        assert.strictEqual(proxy.password, password);

        assert.strictEqual(proxy.network, 'ws');

        assert.strictEqual(proxy['ws-opts'].path, wsPath);

        assert.strictEqual(proxy['ws-opts'].headers.Host, wsHost);

        const produced = ClashMetaProducer().produce([proxy], 'internal');

        assert.strictEqual(produced.length, 1);
        assert.strictEqual(produced[0].type, 'socks5');
        assert.strictEqual(produced[0].network, 'ws');

        assert.strictEqual(produced[0]['ws-opts'].path, wsPath);

        assert.strictEqual(produced[0]['ws-opts'].headers.Host, wsHost);
    });

    it('parses WSS GOST metadata as websocket with TLS for Mihomo', () => {
        const uri = makeGostSocksUri({
            remarks: 'SOCKS GOST WSS TEST',
            gost: {
                route: 'wss',
                host: 'tls.example.invalid',
                path: '/secure-gost',
            },
        });

        const proxy = parseProxy(uri);

        assert.strictEqual(proxy.type, 'socks5');
        assert.strictEqual(proxy.network, 'ws');
        assert.strictEqual(proxy.tls, true);

        assert.strictEqual(proxy['ws-opts'].path, '/secure-gost');
        assert.strictEqual(
            proxy['ws-opts'].headers.Host,
            'tls.example.invalid',
        );

        const produced = ClashMetaProducer().produce([proxy], 'internal');

        assert.strictEqual(produced.length, 1);
        assert.strictEqual(produced[0].type, 'socks5');
        assert.strictEqual(produced[0].network, 'ws');
        assert.strictEqual(produced[0].tls, true);
        assert.strictEqual(produced[0]['ws-opts'].path, '/secure-gost');
        assert.strictEqual(
            produced[0]['ws-opts'].headers.Host,
            'tls.example.invalid',
        );
    });

    it('accepts websocket route aliases, overrides endpoint, and applies websocket defaults', () => {
        const uri = makeGostSocksUri({
            server: '203.0.113.20',
            port: 1080,
            remarks: 'SOCKS GOST DEFAULTS TEST',
            gost: {
                route: ' WebSocket ',
                address: '198.51.100.25',
                port: '9443',
            },
        });

        const proxy = parseProxy(uri);

        assert.strictEqual(proxy.type, 'socks5');

        assert.strictEqual(proxy.server, '198.51.100.25');
        assert.strictEqual(proxy.port, 9443);

        assert.strictEqual(proxy.network, 'ws');
        assert.strictEqual(proxy.tls, undefined);

        assert.strictEqual(proxy['ws-opts'].path, '/');
        assert.strictEqual(
            proxy['ws-opts'].headers.Host,
            '198.51.100.25',
        );
    });

    it('rejects unsupported GOST SOCKS routes', () => {
        const uri = makeGostSocksUri({
            gost: {
                route: 'tcp',
            },
        });

        assert.throws(
            () => parseProxy(uri),
            /unsupported GOST SOCKS route: tcp/,
        );
    });

    it('rejects invalid GOST SOCKS override ports', () => {
        const uri = makeGostSocksUri({
            gost: {
                route: 'ws',
                port: 'not-a-port',
            },
        });

        assert.throws(
            () => parseProxy(uri),
            /invalid GOST SOCKS port: not-a-port/,
        );
    });

    it('keeps legacy socks URIs on the original non-websocket path', () => {
        const auth = encodeURIComponent(
            Base64.encode('legacy-user:legacy-password'),
        );

        const uri =
            `socks://${auth}@198.51.100.30:1080` +
            '#Legacy%20SOCKS';

        const proxy = parseProxy(uri);

        assert.strictEqual(proxy.name, 'Legacy SOCKS');
        assert.strictEqual(proxy.type, 'socks5');

        assert.strictEqual(proxy.server, '198.51.100.30');
        assert.strictEqual(proxy.port, 1080);

        assert.strictEqual(proxy.username, 'legacy-user');
        assert.strictEqual(proxy.password, 'legacy-password');

        assert.strictEqual(proxy.network, undefined);
        assert.strictEqual(proxy['ws-opts'], undefined);
        assert.strictEqual(proxy.tls, undefined);
    });

});
