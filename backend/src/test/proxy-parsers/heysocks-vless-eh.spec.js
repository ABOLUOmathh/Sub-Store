import { expect } from 'chai';
import { ProxyUtils } from '../../core/proxy-utils';

describe('HeySocks VLESS e/h compatibility', function () {
    const UUID = '11111111-2222-3333-4444-555555555555';
    const H = '31' + '00'.repeat(49);

    function parseOne(uri) {
        const proxies = ProxyUtils.parse(uri);

        expect(proxies).to.have.length(1);

        return proxies[0];
    }

    function buildProxy(overrides = {}) {
        return {
            type: 'vless',
            name: 'HeySocks EH',
            server: 'vless.example.com',
            port: 443,
            uuid: UUID,
            network: 'tcp',
            tls: true,
            flow: 'xtls-rprx-vision',
            sni: 'mask.example.com',
            'client-fingerprint': 'chrome',
            'reality-opts': {
                'public-key': 'probe-public-key',
                'short-id': '08',
            },
            udp: true,
            ...overrides,
        };
    }

    it('parses HeySocks VLESS e=1 and h into explicit fields', function () {
        const proxy = parseOne(
            `vless://${UUID}@vless.example.com:443` +
                '?type=tcp' +
                '&security=reality' +
                '&sni=mask.example.com' +
                '&fp=chrome' +
                '&flow=xtls-rprx-vision' +
                '&pbk=probe-public-key' +
                '&sid=08' +
                '&e=1' +
                `&h=${H}` +
                '#HeySocks%20EH',
        );

        expect(proxy.e).to.equal(true);
        expect(proxy.h).to.equal(H);
    });

    it('accepts boolean-style e values and preserves explicit false', function () {
        const enabled = parseOne(
            `vless://${UUID}@vless.example.com:443` +
                '?type=tcp&security=tls&e=true' +
                '#HeySocks%20E%20True',
        );

        const disabled = parseOne(
            `vless://${UUID}@vless.example.com:443` +
                '?type=tcp&security=tls&e=0' +
                '#HeySocks%20E%20False',
        );

        expect(enabled.e).to.equal(true);
        expect(disabled).to.have.property('e', false);
    });

    it('produces canonical e=1 and h and round-trips them', function () {
        const source = buildProxy({
            e: true,
            h: H,
        });

        const encoded = ProxyUtils.produce(
            [source],
            'URI',
            'external',
        ).trim();

        expect(encoded).to.include('&e=1');
        expect(encoded).to.include(`&h=${H}`);

        const reparsed = parseOne(encoded);

        expect(reparsed.e).to.equal(true);
        expect(reparsed.h).to.equal(H);
    });

    it('does not invent e or h for ordinary VLESS URIs', function () {
        const proxy = parseOne(
            `vless://${UUID}@vless.example.com:443` +
                '?type=tcp&security=tls' +
                '#Ordinary%20VLESS',
        );

        expect(proxy).to.not.have.property('e');
        expect(proxy).to.not.have.property('h');

        const encoded = ProxyUtils.produce(
            [buildProxy()],
            'URI',
            'external',
        ).trim();

        expect(encoded).to.not.match(/[?&]e=/);
        expect(encoded).to.not.match(/[?&]h=/);
    });

    it('already preserves internal e/h through the Mihomo producer', function () {
        const source = buildProxy({
            e: true,
            h: H,
        });

        const output = ProxyUtils.produce(
            [source],
            'Mihomo',
            'internal',
        )[0];

        expect(output.e).to.equal(true);
        expect(output.h).to.equal(H);
    });
    it('keeps h independent when e is absent', function () {
        const uri =
            `vless://${UUID}@vless.example.com:443` +
            '?type=tcp&security=tls' +
            `&h=${H}` +
            '#HeySocks%20H%20Only';

        const parsed = parseOne(uri);

        expect(parsed.h).to.equal(H);
        expect(parsed).to.not.have.property('e');

        const encoded = ProxyUtils.produce(
            [buildProxy({ h: H })],
            'URI',
            'external',
        ).trim();

        expect(encoded).to.include(`&h=${H}`);
        expect(encoded).to.not.match(/[?&]e=/);
    });

    it('produces explicit e=false canonically as e=0', function () {
        const encoded = ProxyUtils.produce(
            [buildProxy({ e: false })],
            'URI',
            'external',
        ).trim();

        expect(encoded).to.include('&e=0');
        expect(encoded).to.not.match(/[?&]h=/);

        const reparsed = parseOne(encoded);

        expect(reparsed).to.have.property('e', false);
        expect(reparsed).to.not.have.property('h');
    });

    it('preserves uppercase hex h without normalizing its spelling', function () {
        const upperH = '31AABBCCDDEE';

        const parsed = parseOne(
            `vless://${UUID}@vless.example.com:443` +
                '?type=tcp&security=tls' +
                `&h=${upperH}` +
                '#Uppercase%20H',
        );

        expect(parsed.h).to.equal(upperH);

        const encoded = ProxyUtils.produce(
            [buildProxy({ h: upperH })],
            'URI',
            'external',
        ).trim();

        expect(encoded).to.include(`&h=${upperH}`);
    });

    it('rejects invalid HeySocks VLESS e values', function () {
        const parsed = ProxyUtils.parse(
            `vless://${UUID}@vless.example.com:443` +
                '?type=tcp&security=tls&e=2' +
                '#Invalid%20E',
        );

        expect(parsed).to.have.length(0);
    });

    it('rejects non-hex and odd-length HeySocks VLESS h values', function () {
        const nonHex = ProxyUtils.parse(
            `vless://${UUID}@vless.example.com:443` +
                '?type=tcp&security=tls&h=31zz' +
                '#Invalid%20H',
        );

        const oddLength = ProxyUtils.parse(
            `vless://${UUID}@vless.example.com:443` +
                '?type=tcp&security=tls&h=abc' +
                '#Odd%20H',
        );

        expect(nonHex).to.have.length(0);
        expect(oddLength).to.have.length(0);
    });

    it('rejects an explicitly empty HeySocks VLESS h value', function () {
        const parsed = ProxyUtils.parse(
            `vless://${UUID}@vless.example.com:443` +
                '?type=tcp&security=tls&h=' +
                '#Empty%20H',
        );

        expect(parsed).to.have.length(0);
    });

});
