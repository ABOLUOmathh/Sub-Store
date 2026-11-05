import { expect } from 'chai';
import { ProxyUtils } from '../core/proxy-utils';
import Processors from '../core/proxy-utils/processors';

describe('custom Trojan URI name KAT', () => {
    it('keeps fragment name when query is absent', () => {
        const raw =
            'trojan://test-password@example.com:443#' +
            encodeURIComponent('🇯🇵 Japan');

        const proxies = ProxyUtils.parse(raw);

        expect(proxies).to.have.length(1);

        const proxy = proxies[0];

        expect(proxy.type).to.equal('trojan');
        expect(proxy.server).to.equal('example.com');
        expect(proxy.port).to.equal(443);
        expect(proxy.name).to.equal('🇯🇵 Japan');
    });

    it('keeps fragment name when query is present', () => {
        const raw =
            'trojan://test-password@example.com:443' +
            '?allowInsecure=1&peer=example.org#' +
            encodeURIComponent('🇯🇵 Japan');

        const proxies = ProxyUtils.parse(raw);

        expect(proxies).to.have.length(1);

        const proxy = proxies[0];

        expect(proxy.name).to.equal('🇯🇵 Japan');
        expect(proxy.port).to.equal(443);
        expect(proxy.sni).to.equal('example.org');
    });

    it('parser preserves source Taiwan name', () => {
        const raw =
            'trojan://test-password@example.com:443#' +
            encodeURIComponent('🇨🇳 Taiwan');

        const [proxy] = ProxyUtils.parse(raw);

        expect(proxy.name).to.equal('🇨🇳 Taiwan');
    });

    it('geo classifier recognizes Taiwan by text', () => {
        expect(
            ProxyUtils.getFlag('🇨🇳 Taiwan')
        ).to.equal('🇹🇼');

        expect(
            ProxyUtils.getFlag('Taiwan')
        ).to.equal('🇹🇼');

        expect(
            ProxyUtils.getFlag('🇨🇳 China')
        ).to.equal('🇨🇳');
    });
});


describe('custom Taiwan flag policy KAT', () => {
    const applyFlag = (name, options = {}) => {
        const operator = Processors['Flag Operator']({
            mode: 'add',
            ...options,
        });

        const [proxy] = operator.func([
            {
                name,
                type: 'trojan',
                server: 'example.com',
                port: 443,
            },
        ]);

        return proxy.name;
    };

    it('repairs mismatched China flag on Taiwan name', () => {
        expect(
            applyFlag('🇨🇳 Taiwan')
        ).to.equal('🇹🇼 Taiwan');
    });

    it('adds Taiwan flag to plain Taiwan name', () => {
        expect(
            applyFlag('Taiwan')
        ).to.equal('🇹🇼 Taiwan');
    });

    it('keeps Taiwan flag with explicit tw policy', () => {
        expect(
            applyFlag('🇹🇼 Taiwan', { tw: 'tw' })
        ).to.equal('🇹🇼 Taiwan');
    });

    it('does not change genuine China name to Taiwan', () => {
        expect(
            applyFlag('🇨🇳 China')
        ).to.equal('🇨🇳 China');
    });

    it('preserves legacy ws compatibility mode', () => {
        expect(
            applyFlag('🇹🇼 Taiwan', { tw: 'ws' })
        ).to.equal('🇼🇸 Taiwan');
    });
});

describe('custom Trojan port regression KAT', () => {
    it('keeps explicit non-default port without query', () => {
        const raw =
            'trojan://test-password@example.com:7080#' +
            encodeURIComponent('🇭🇰 Hong Kong');

        const [proxy] = ProxyUtils.parse(raw);

        expect(proxy.name).to.equal('🇭🇰 Hong Kong');
        expect(proxy.server).to.equal('example.com');
        expect(proxy.port).to.equal(7080);
    });

    it('adds default 443 when port is absent and keeps fragment', () => {
        const raw =
            'trojan://test-password@example.com#' +
            encodeURIComponent('🇯🇵 Japan');

        const [proxy] = ProxyUtils.parse(raw);

        expect(proxy.name).to.equal('🇯🇵 Japan');
        expect(proxy.server).to.equal('example.com');
        expect(proxy.port).to.equal(443);
    });

    it('keeps explicit non-default port with query', () => {
        const raw =
            'trojan://test-password@example.com:7080' +
            '?allowInsecure=1&peer=example.org#' +
            encodeURIComponent('🇭🇰 Hong Kong');

        const [proxy] = ProxyUtils.parse(raw);

        expect(proxy.name).to.equal('🇭🇰 Hong Kong');
        expect(proxy.port).to.equal(7080);
        expect(proxy.sni).to.equal('example.org');
    });
});
