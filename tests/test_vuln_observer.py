import unittest
import json

from vuln_observer import VulnObserver

class TestVulnObserver(unittest.TestCase):
    @classmethod
    def setUpClass(self):
        self.vo = VulnObserver('tests/wifid_14.1')
        self.addr = 0x1000f5380

    def test_esil_get_nb_branches(self):
        estr = 'x19,x0,=pc,lr,=,4295968680,pc,=120,x29,-,DUP,tmp,=,[8],x27,=x27,!,?{,4295971932,pc,=,}'

        self.assertEqual(self.vo.esil_get_nb_branches(estr), 2)

    def test_esil_emulate(self):
        regs = self.vo.esil_emulate(self.addr, 'pc,=', 1)
        self.assertEqual(regs['pc'], 0x1000f5390)
    
    def test_get_fct_range(self):
        start, end = self.vo.get_fct_range(self.addr)
        self.assertEqual(start, 0x1000f4ef8)
        self.assertEqual(end, 0x1000f56c4)

    def test_get_bbs(self):
        bbs = self.vo.get_bbs(self.addr)
        self.assertEqual(len(bbs), 83)

    def test_get_bb_id(self):
        bb_ids = self.vo.get_bb_ids([self.addr])
        self.assertEqual(bb_ids[0], 49)

    def test_get_memreads(self):
        self.assertEqual(len(self.vo.get_memreads(self.addr)), 1)
    
    def test_read_at(self):
        expected = [224,3,19,170,9,253,255,151]
        self.assertEqual(self.vo.read_at(self.addr, 8), bytes(expected))

    def test_search_vuln_ok(self):
        f = open('tests/wifid.json')
        self.assertTrue(self.vo.search_vuln(f))
        f.close()

    def test_search_vuln_ko(self):
        f = open('tests/wifid.json')
        vo = VulnObserver('tests/wifid_14.7.1')
        self.assertFalse(vo.search_vuln(f))
        f.close()

    def test_get_graph_ok(self):
        gfile = '/tmp/vo_test_graph.gml'
        ga = self.vo.get_graph(0x1000f4ef8, save=True, dest=gfile)
        gb = self.vo.get_saved_graph(gfile)
        self.assertTrue(gb.isomorphic(ga))

    def test_get_graph_ko(self):
        gfile = '/tmp/vo_test_graph.gml'
        ga = self.vo.get_graph(0x1000f4ef8, save=True, dest=gfile)
        gb = self.vo.get_saved_graph(gfile)
        gb.delete_edges(22)
        self.assertFalse(gb.isomorphic(ga))

    def test_handle_id_symbol_fct(self):
        candidates = []
        id = json.loads(
            '{"type": "symbol",'
            '"name": "_Apple80211Open",'
            '"is_function": true,'
            '"class": ""}'
        )
        candidates = self.vo.handle_id_symbol(id, candidates)

        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0], 0x10015ea28)

    def test_handle_id_symbol_method(self):
        candidates = []
        id = json.loads(
            '{"type": "symbol",'
            '"name": "sharedInstance",'
            '"is_function": true,'
            '"class": "WiFiCloudAssetsClient"}'
        )
        candidates = self.vo.handle_id_symbol(id, candidates)

        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0], 0x1000025c0)

    def test_handle_att_function_notfound(self):
        function = json.loads('{"type": "FUNCTION", "fct_id": 1, "identifiers": ['
            '{"type": "symbol", "name": "sharedInstance", "is_function": true,'
            '"class": "WiFiCloudAssetsClient"},'
            '{"type": "symbol", "name": "_Apple80211Open", "is_function": true,'
            '"class": ""} ] }'
        )
        fct_id = function['fct_id']
        print(f'fct_id = {fct_id}')
        found = self.vo.handle_att_function(function['identifiers'], fct_id)

        self.assertEqual(len(self.vo.fct_candidates[fct_id]), 0)
        self.assertFalse(found)

if __name__ == '__main__':
    unittest.main()
