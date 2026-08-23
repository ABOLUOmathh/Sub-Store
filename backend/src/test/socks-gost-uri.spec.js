import assert from 'assert';
import { Base64 } from 'js-base64';

import parsers from '../core/proxy-utils/parsers';
import ClashMetaProducer from '../core/proxy-utils/producers/clashmeta';

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
});
