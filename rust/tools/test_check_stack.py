#!/usr/bin/env python3
"""Disassembly-format regressions for the firmware's stack gate."""
import importlib.util
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import unittest

spec = importlib.util.spec_from_file_location('check_stack', Path(__file__).with_name('check_stack.py'))
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)

class Frames(unittest.TestCase):
    def read(self, text):
        with patch.object(check.subprocess, 'run', return_value=SimpleNamespace(stdout=text)):
            return dict((name, size) for size, name in check.frames('image', 'objdump'))

    def test_hexadecimal_frames_are_not_zero(self):
        got = self.read('42000000 <small>:\n entry a1, 240\n42000100 <large>:\n entry a1, 0x64d0\n')
        self.assertEqual(got, {'small': 240, 'large': 25808})
        self.assertGreater(got['large'], 12288)

    def test_large_frame_extra_subtraction(self):
        got = self.read('42000000 <oversize>:\n entry a1, 0x100\n movi a2, 0x200\n sub a3, a1, a2\n movsp a1, a3\n')
        self.assertEqual(got['oversize'], 768)

    def test_hexadecimal_addmi(self):
        self.assertEqual(self.read('42000000 <extra>:\n entry a1, 32\n addmi a1, a1, -0x100\n')['extra'], 288)

if __name__ == '__main__':
    unittest.main()
