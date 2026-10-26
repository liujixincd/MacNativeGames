"""Synthetic Atmosphere instructions exercise the static cheat importer."""
import importlib.util
import argparse
import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'games/totk/scripts'))
import cheat_mod

BUILD = '0123456789abcdef' * 2 + '00112233'


class CheatImport(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.file = self.root / (BUILD[:16].upper() + '.txt')
        self.file.write_text('[First #1]\n04000000 00000100 11223344\n'
                             '[Second]\n08000000 00000200 01234567 89ABCDEF\n'
                             '[Pointer]\n580F0000 00000300\n')

    def test_only_selected_cheats_and_little_endian_values(self):
        text, report = cheat_mod.selection(self.file, ['Second'], BUILD)
        self.assertIn('00000200 EFCDAB8967452301', text)
        self.assertNotIn('00000100', text)
        self.assertEqual(report['selected'], ['Second'])
        self.assertIn('@nsobid-' + BUILD, text)
        self.assertIn('@flag offset_shift 0x100', text)

    def test_main_static_word_and_subword_widths(self):
        self.assertEqual(cheat_mod.static_writes('small', [0x01000000, 8, 0xFF]), [(8, b'\xff')])
        self.assertEqual(cheat_mod.static_writes('small', [0x02000000, 8, 0x1234]), [(8, b'\x34\x12')])
        text, _ = cheat_mod.selection(self.file, ['First #1'], BUILD)
        self.assertIn('00000100 44332211', text)

    def test_wrong_build_and_no_or_unknown_selection(self):
        for names, build in ((['First #1'], 'f' * 40), ([], BUILD), (['Missing'], BUILD)):
            with self.assertRaises(cheat_mod.CheatError):
                cheat_mod.selection(self.file, names, build)

    def test_nonstatic_and_truncated_codes_are_not_partially_imported(self):
        for words in ([0x580F0000, 0], [0x04010000, 0, 0], [0x04100000, 0, 0],
                      [0x04000000, 0], [0x01000000, 0, 256], [0x80000001],
                      [0x010000FF, 0xFFFFFFFF, 0xFF, 0x020000FF, 0xFFFFFFFF, 0x1234]):
            with self.subTest(words=words), self.assertRaises(cheat_mod.CheatError):
                cheat_mod.static_writes('unsupported', words)
        with self.assertRaisesRegex(cheat_mod.CheatError, 'not a static'):
            cheat_mod.prepare_mod(self.file, ['Pointer'], BUILD, self.root / 'work')
        self.assertFalse((self.root / 'work').exists())

    def test_duplicate_names_and_broken_sections(self):
        for text in ('[One]\n[One]\n', '[Broken\n', '04000000 0 1', '[One]\nXYZ'):
            with self.assertRaises(cheat_mod.CheatError):
                cheat_mod.parse_cheats(text)

    def test_master_required_but_conflicting_cheats_rejected(self):
        self.file.write_text('{Master}\n04000000 00000100 11223344\n'
                             '[Choice]\n04000000 00000200 55667788\n'
                             '[Conflict]\n04000000 00000100 00000000\n')
        text, report = cheat_mod.selection(self.file, ['Choice'], BUILD)
        self.assertIn('00000100 44332211', text)
        self.assertEqual(report['masters'], ['Master'])
        with self.assertRaisesRegex(cheat_mod.CheatError, 'conflicts'):
            cheat_mod.selection(self.file, ['Conflict'], BUILD)

    def test_combining_mod_preserves_original_and_records_provenance(self):
        mod = self.root / 'mod'
        (mod / 'exefs').mkdir(parents=True)
        (mod / 'exefs/original.ips').write_bytes(b'fixture')
        folder, report = cheat_mod.prepare_mod(self.file, ['First #1'], BUILD, self.root / 'work', mod)
        self.assertEqual((folder / 'exefs/original.ips').read_bytes(), b'fixture')
        self.assertFalse((mod / 'exefs/mng-selected-cheats.pchtxt').exists())
        record = json.loads((folder / 'cheats-selection.json').read_text())
        self.assertEqual(record, report)
        self.assertEqual(len(record['patch_sha256']), 64)

    def test_generated_patch_is_accepted_by_existing_pchtxt_parser(self):
        try:
            import mod_exefs
        except ImportError as error:
            self.skipTest(str(error))
        text, _ = cheat_mod.selection(self.file, ['First #1'], BUILD)
        records = mod_exefs.parse_pchtxt(text, BUILD, Path('synthetic.pchtxt'))
        self.assertEqual(records, [(0x100, bytes.fromhex('44332211'))])
        with self.assertRaises(mod_exefs.ModError):
            mod_exefs.parse_pchtxt(text, 'f' * 40, Path('synthetic.pchtxt'))

    def test_generated_mod_changes_only_selected_bytes_in_original_nso(self):
        import mod_exefs
        import test_mod_exefs as fixture
        build_id = fixture.BUILD_ID.hex() + '00000000'
        file = self.root / (build_id[:16] + '.txt')
        file.write_text('[Selected]\n04000000 00000100 11223344\n'
                        '[Unused]\n04000000 00000110 55667788\n')
        folder, _ = cheat_mod.prepare_mod(file, ['Selected'], build_id, self.root / 'work')
        exefs = self.root / 'retail'
        exefs.mkdir()
        raw = fixture.nso_bytes()
        (exefs / 'main').write_bytes(raw)
        output = self.root / 'patched-main'
        with contextlib.redirect_stdout(io.StringIO()):
            report = mod_exefs.apply(argparse.Namespace(exefs=exefs, mod=folder, version='v0',
                                                        output=output, report=self.root / 'report.json'))
        image = fixture.image_of(output.read_bytes())
        original = fixture.image_of(raw)
        self.assertEqual(image[0x100:0x104], bytes.fromhex('44332211'))
        self.assertEqual(image[:0x100], original[:0x100])
        self.assertEqual(image[0x104:], original[0x104:])
        self.assertEqual((exefs / 'main').read_bytes(), raw)
        self.assertEqual(report['status'], 'pass')

    def test_generated_mod_cannot_bypass_reserved_site_checks(self):
        import mod_exefs
        import patch_sites
        import test_mod_exefs as fixture
        build_id = fixture.BUILD_ID.hex() + '00000000'
        file = self.root / (build_id[:16] + '.txt')
        file.write_text('[Reserved]\n04000000 00000100 11223344\n')
        folder, _ = cheat_mod.prepare_mod(file, ['Reserved'], build_id, self.root / 'work')
        exefs = self.root / 'retail'
        exefs.mkdir()
        (exefs / 'main').write_bytes(fixture.nso_bytes())
        with mock.patch.object(patch_sites, 'sites', return_value=[patch_sites.Site('runtime feature', 0x100, 4)]):
            with self.assertRaisesRegex(mod_exefs.ModError, 'runtime patches itself'):
                mod_exefs.apply(argparse.Namespace(exefs=exefs, mod=folder, version='v0',
                                                  output=self.root / 'patched', report=self.root / 'report.json'))

    def test_selection_record_is_packaged_with_game_data(self):
        spec = importlib.util.spec_from_file_location('build_for_record', ROOT / 'build_app.py')
        build = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(build)
        _, record = cheat_mod.selection(self.file, ['First #1'], BUILD)
        data = self.root / 'tree/build/game-data/v0'
        data.mkdir(parents=True)
        for name in build.game_data_files('v0'):
            (data / name).write_bytes(b'synthetic data')
        analysis = self.root / 'tree/analysis'
        analysis.mkdir()
        (analysis / 'phase12-validation.json').write_text(json.dumps({'cheats': record}))
        destination = self.root / 'resources'
        build.place_game_data(self.root / 'tree', destination, 'v0')
        self.assertEqual(json.loads((destination / 'build/game-data/v0/cheats-selection.json').read_text()), record)

    def test_build_cli_requires_explicit_selection(self):
        spec = importlib.util.spec_from_file_location('build_for_cheats', ROOT / 'build_app.py')
        build = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(build)
        for args in (['--cheats', str(self.file)], ['--enable-cheat', 'First #1'],
                     ['--cheats', str(self.file), '--enable-cheat', 'Pointer']):
            with self.subTest(args=args), self.assertRaises(build.BuildError):
                build.main(['absent.xci', '-k', 'absent.keys'] + args)
        options = build.parse_args(['game.xci', '-k', 'keys', '--cheats', str(self.file),
                                    '--enable-cheat', 'First #1', '--enable-cheat', 'Second'])
        self.assertEqual(options.enable_cheat, ['First #1', 'Second'])


if __name__ == '__main__':
    unittest.main()
