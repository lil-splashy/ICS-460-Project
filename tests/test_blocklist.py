import unittest

from adblock import blocklist, load_blocklist


class TestBlocklist(unittest.TestCase):
    def test_exact_match(self):
        entries = load_blocklist('blocklist.txt')
        self.assertTrue(blocklist.is_blocked('ads.com', entries))
        self.assertFalse(blocklist.is_blocked('other.com', entries))


if __name__ == '__main__':
    unittest.main()
