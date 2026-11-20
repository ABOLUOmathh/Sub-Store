import { expect } from 'chai';
import { ProxyUtils } from '@/core/proxy-utils';
import {
    expectSubset,
    loadProducedJson,
    produceInternal,
    UUID,
} from './helpers';

describe('HeySocks 4 custom protocols for sing-box export', function () {
    const H = '31' + '00'.repeat(49);

    it('exports Enhanced VLESS with e and h tokens and REALITY options to sing-box', function () {
        const vlessProxy = {
            type: 'vless',
            name: 'HeySocks VLESS-EH Node',
            server: 'vless.example.com',
            port: 443,
            uuid: UUID,
            network: 'tcp',
            tls: true,
            flow: 'xtls-rprx-vision',
            sni: 'itunes.apple.com',
            'client-fingerprint': 'chrome',
            'reality-opts': {
                'public-key': 'xSt8a6p4s4mff2XyvT6fJ9e14m6oD8iVwE1p7R1293Y',
                'short-id': '90ba95bf',
            },
            e: true,
            h: H,
            udp: true,
        };

        const json = loadProducedJson('sing-box', vlessProxy);
        expect(json.outbounds).to.have.length(1);

        const outbound = json.outbounds[0];
        expect(outbound.type).to.equal('vless');
        expect(outbound.tag).to.equal('HeySocks VLESS-EH Node');
        expect(outbound.server).to.equal('vless.example.com');
        expect(outbound.server_port).to.equal(443);
        expect(outbound.uuid).to.equal(UUID);
        expect(outbound.flow).to.equal('xtls-rprx-vision');
        expect(outbound.e).to.equal(true);
        expect(outbound.h).to.equal(H);

        expect(outbound.tls).to.be.an('object');
        expect(outbound.tls.enabled).to.equal(true);
        expect(outbound.tls.server_name).to.equal('itunes.apple.com');
        expect(outbound.tls.reality.enabled).to.equal(true);
        expect(outbound.tls.reality.public_key).to.equal(
            'xSt8a6p4s4mff2XyvT6fJ9e14m6oD8iVwE1p7R1293Y',
        );
        expect(outbound.tls.reality.short_id).to.equal('90ba95bf');
        expect(outbound.tls.utls.enabled).to.equal(true);
        expect(outbound.tls.utls.fingerprint).to.equal('chrome');
        expect(outbound.tls.disable_x25519_mlkem768).to.equal(true);
    });

    it('exports HeySocks XHTTP to sing-box with heysocks-xhttp outbound type', function () {
        const xhttpProxy = {
            type: 'xhttp',
            name: 'HeySocks XHTTP Node',
            server: '144.225.53.149',
            port: 12443,
            password: 'test-key:314033d0b9499722aa91ff37da0aba1b',
            cipher: 'aes-128-ctr',
            'padding-len': '8-64',
            udp: true,
            'udp-over-tcp': true,
            e: true,
            'fake-net': {
                tcp: 'd1773e83bccd9ef65e4e4869a6476774',
                udp: '27bc401e06ad7591e32d483505d9c5e8',
            },
        };

        const json = loadProducedJson('sing-box', xhttpProxy);
        expect(json.outbounds).to.have.length(1);

        const outbound = json.outbounds[0];
        expect(outbound.type).to.equal('heysocks-xhttp');
        expect(outbound.tag).to.equal('HeySocks XHTTP Node');
        expect(outbound.server).to.equal('144.225.53.149');
        expect(outbound.server_port).to.equal(12443);
        expect(outbound.password).to.equal(
            'test-key:314033d0b9499722aa91ff37da0aba1b',
        );
        expect(outbound.cipher).to.equal('aes-128-ctr');
        expect(outbound.padding_len).to.equal('8-64');
        expect(outbound.udp_over_tcp).to.equal(true);
        expect(outbound.e).to.equal(true);

        expect(outbound.fake_net).to.be.an('object');
        expect(outbound.fake_net['fake-tcp']).to.equal(
            'd1773e83bccd9ef65e4e4869a6476774',
        );
        expect(outbound.fake_net['fake-udp']).to.equal(
            '27bc401e06ad7591e32d483505d9c5e8',
        );
        expect(outbound.fake_net.tcp).to.equal(
            'd1773e83bccd9ef65e4e4869a6476774',
        );
        expect(outbound.fake_net.udp).to.equal(
            '27bc401e06ad7591e32d483505d9c5e8',
        );
    });

    it('exports OneSocks to sing-box with onesocks outbound type', function () {
        const onesocksProxy = {
            type: 'os',
            name: 'HeySocks OneSocks Node',
            server: '154.9.241.144',
            port: 443,
            password: 'secret-password',
            cipher: 'aes-128-ctr',
            'padding-len': '8-64',
            udp: true,
            'udp-over-tcp': true,
            e: true,
        };

        const json = loadProducedJson('sing-box', onesocksProxy);
        expect(json.outbounds).to.have.length(1);

        const outbound = json.outbounds[0];
        expect(outbound.type).to.equal('onesocks');
        expect(outbound.tag).to.equal('HeySocks OneSocks Node');
        expect(outbound.server).to.equal('154.9.241.144');
        expect(outbound.server_port).to.equal(443);
        expect(outbound.password).to.equal('secret-password');
        expect(outbound.cipher).to.equal('aes-128-ctr');
        expect(outbound.padding_len).to.equal('8-64');
        expect(outbound.udp_over_tcp).to.equal(true);
        expect(outbound.e).to.equal(true);
    });

    it('exports Shadowsocks 2022 Blackstone to sing-box with automatic UOT and Blackstone password', function () {
        const ssProxy = {
            type: 'ss',
            name: 'Blackstone SS Node',
            server: '103.85.74.25',
            port: 27010,
            cipher: '2022-blake3-aes-128-gcm',
            password:
                'uyWXYYxUnxaUentAvSiJ5w==:MTc1NTQyMjA0M0xsSXhBaA==#BLACKSTONE',
            uot: true,
        };

        const json = loadProducedJson('sing-box', ssProxy);
        expect(json.outbounds).to.have.length(1);

        const outbound = json.outbounds[0];
        expect(outbound.type).to.equal('shadowsocks');
        expect(outbound.tag).to.equal('Blackstone SS Node');
        expect(outbound.server).to.equal('103.85.74.25');
        expect(outbound.server_port).to.equal(27010);
        expect(outbound.method).to.equal('2022-blake3-aes-128-gcm');
        expect(outbound.password).to.equal(
            'uyWXYYxUnxaUentAvSiJ5w==:MTc1NTQyMjA0M0xsSXhBaA==#BLACKSTONE',
        );
        expect(outbound.udp_over_tcp).to.equal(true);
    });

    it('parses un-base64 SIP002 URI with percent-encoded # in password and produces sing-box config', function () {
        const uri =
            'ss://2022-blake3-aes-128-gcm:uyWXYYxUnxaUentAvSiJ5w==:MTc1NTQyMjA0M0xsSXhBaA==%23BLACKSTONE@103.85.74.25:27010?uot=1#Node-Encoded-Blackstone';
        const [parsed] = ProxyUtils.parse(uri);
        expect(parsed.password).to.equal(
            'uyWXYYxUnxaUentAvSiJ5w==:MTc1NTQyMjA0M0xsSXhBaA==#BLACKSTONE',
        );

        const json = loadProducedJson('sing-box', parsed);
        expect(json.outbounds).to.have.length(1);
        expect(json.outbounds[0].type).to.equal('shadowsocks');
        expect(json.outbounds[0].password).to.equal(
            'uyWXYYxUnxaUentAvSiJ5w==:MTc1NTQyMjA0M0xsSXhBaA==#BLACKSTONE',
        );
    });

    it('round-trips all 4 URI protocols from links into sing-box config', function () {
        const uris = [
            // 1. Enhanced VLESS
            `vless://${UUID}@194.38.23.237:10443?type=tcp&security=reality&sni=itunes.apple.com&fp=chrome&flow=xtls-rprx-vision&pbk=xSt8a6p4s4mff2XyvT6fJ9e14m6oD8iVwE1p7R1293Y&sid=90ba95bf&e=1&h=${H}#Node-VLESS`,
            // 2. HeySocks XHTTP
            'xhttp://f355229a246501c6b3cf735aecd2df9c%3A314033d0b9499722aa91ff37da0aba1b@144.225.53.149:12443?v=1&cipher=aes-128-ctr&udp=1&uot=1&uot-version=0&padding=8-64&e=1&fake-tcp=d1773e83bccd&fake-udp=27bc401e06ad#Node-XHTTP',
            // 3. OneSocks
            'os://uyWXYYxUnxaUentAvSiJ5w%3D%3D%3AMTc1NTQyMjA0M0xsSXhBaA%3D%3D@154.9.241.144:443?v=1&cipher=aes-128-ctr&udp=1&uot=1&padding=8-64&e=1#Node-OneSocks',
            // 4. SS 2022 Blackstone (base64 authority format as shared by real providers)
            'ss://MjAyMi1ibGFrZTMtYWVzLTEyOC1nY206dXlXWFlZeFVueGFVZW50QXZTaUo1dz09Ok1UYzFOVFF5TWpBME0weHNTWGhCYUE9PSNCTEFDS1NUT05FQDEwMy44NS43NC4yNToyNzAxMA?uot=1#Node-Blackstone',
        ];

        const parsedProxies = ProxyUtils.parse(uris.join('\n'));
        expect(parsedProxies).to.have.length(4);

        const singboxJson = loadProducedJson('sing-box', parsedProxies);
        expect(singboxJson.outbounds).to.have.length(4);

        const types = singboxJson.outbounds.map((o) => o.type);
        expect(types).to.deep.equal([
            'vless',
            'heysocks-xhttp',
            'onesocks',
            'shadowsocks',
        ]);

        const vlessOutbound = singboxJson.outbounds[0];
        expect(vlessOutbound.e).to.equal(true);
        expect(vlessOutbound.h).to.equal(H);

        const xhttpOutbound = singboxJson.outbounds[1];
        expect(xhttpOutbound.fake_net['fake-tcp']).to.equal('d1773e83bccd');

        const osOutbound = singboxJson.outbounds[2];
        expect(osOutbound.cipher).to.equal('aes-128-ctr');

        const ssOutbound = singboxJson.outbounds[3];
        expect(ssOutbound.method).to.equal('2022-blake3-aes-128-gcm');
    });
});
