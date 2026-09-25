"""Stash 3.4.1 provider benchmarks must not weaken exit-consistent DNS."""
import copy
import unittest

from lib.clash_bundle import apply_stash_benchmark


class StashBenchmarkTests(unittest.TestCase):
    def config(self):
        return {
            'proxies': [{'name': 'Exit', 'server': 'proxy.example.test', 'type': 'trojan'}],
            'proxy-providers': {'airport-example': {
                'type': 'http', 'url': 'https://example.test/sub?token=private',
                'proxy': 'BOOTSTRAP', 'headers': {'Authorization': 'Bearer secret'},
                'health-check': {'url': 'https://8.8.8.8/generate_204', 'interval': 300},
                'override': {'additional-prefix': '[Example] '},
            }},
            'proxy-groups': [{'name': 'PROXY', 'type': 'select', 'proxies': ['Germany']},
                             {'name': 'Germany', 'type': 'url-test', 'use': ['airport-example']}],
            'dns': {'follow-rule': True, 'respect-rules': True,
                    'nameserver': ['https://8.8.8.8/dns-query#PROXY'],
                    'nameserver-policy': {'example.test': ['https://1.1.1.1/dns-query#BOOTSTRAP']}},
            'rules': ['NETWORK,udp,PROXY', 'NETWORK,udp,REJECT', 'MATCH,PROXY'],
        }

    def test_remote_nodes_get_native_stash_fields_at_provider_level(self):
        config = self.config()
        before = copy.deepcopy(config)
        apply_stash_benchmark(config)
        for adapter in (config['proxies'][0], config['proxy-providers']['airport-example']):
            self.assertEqual(adapter['benchmark-url'], 'http://cp.cloudflare.com/generate_204')
            self.assertEqual(adapter['benchmark-timeout'], 5)
        provider = config['proxy-providers']['airport-example']
        for key, value in before['proxy-providers']['airport-example'].items():
            self.assertEqual(provider[key], value)
        self.assertNotIn('benchmark-url', provider['override'])

    def test_selected_airport_and_dns_exit_graph_are_unchanged(self):
        config = self.config()
        before = copy.deepcopy(config)
        apply_stash_benchmark(config)
        for key in ('dns', 'rules', 'proxy-groups'):
            self.assertEqual(config[key], before[key])
        self.assertNotIn('fallback', config['dns'])
        self.assertNotIn('DIRECT', '\n'.join(config['rules']))
        self.assertTrue(config['dns']['follow-rule'])
        self.assertTrue(config['dns']['respect-rules'])
        once = copy.deepcopy(config)
        apply_stash_benchmark(config)
        self.assertEqual(config, once)

    def test_empty_clean_subscription_does_not_gain_an_airport(self):
        config = {'proxies': [], 'proxy-providers': {}}
        apply_stash_benchmark(config)
        self.assertEqual(config, {'proxies': [], 'proxy-providers': {}})

    def test_malformed_provider_section_is_rejected(self):
        with self.assertRaisesRegex(SystemExit, 'proxy-providers 必须是映射'):
            apply_stash_benchmark({'proxies': [], 'proxy-providers': []})


if __name__ == '__main__':
    unittest.main()
