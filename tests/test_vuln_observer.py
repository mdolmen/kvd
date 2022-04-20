import unittest

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

if __name__ == '__main__':
    unittest.main()
