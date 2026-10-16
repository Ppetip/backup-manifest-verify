import unittest
import tool

class BehaviorTests(unittest.TestCase):
    def test_missing_required_input(self):
        with self.assertRaises((KeyError, ValueError, TypeError)):
            tool.analyze({})


    def test_real_backup_verified_corrupt_and_missing(self):
        import tempfile, hashlib
        from pathlib import Path
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory)/'good').write_bytes(b'abc')
            (Path(directory)/'bad').write_bytes(b'changed')
            expected=hashlib.sha256(b'abc').hexdigest()
            result=tool.verify(directory,{'good':expected,'bad':expected,'missing':expected})
            self.assertEqual([x['kind'] for x in result],['corrupt','verified','missing'])
    def test_traversal_rejected(self):
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            for path in ('../outside','/absolute','C:/private','..\\private'):
                with self.subTest(path=path), self.assertRaises(ValueError): tool.verify(directory,{path:'a'*64})
    def test_invalid_hash_rejected(self):
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError): tool.verify(directory,{'a':'bad'})
    def test_verification_byte_budget(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory)/'a').write_bytes(b'abc')
            with self.assertRaises(ValueError): tool.verify(directory,{'a':'a'*64},2)
