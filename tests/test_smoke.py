import unittest

from app.samples import CustodyService, Sample


class CustodySmokeTest(unittest.TestCase):
    def test_sample_and_health(self):
        self.assertEqual(Sample("S-100", "决赛批次").barcode, "S-100")
        self.assertEqual(CustodyService().health()["status"], "ok")


if __name__ == "__main__":
    unittest.main()

