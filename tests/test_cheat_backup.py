"""Exercise production game-slot acquisition and cheat backups with fake files."""
import fcntl
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(sys.platform == 'darwin', 'Foundation and game-slot probes require macOS')
class CheatBackup(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiler = shutil.which('clang')
        if not compiler:
            raise unittest.SkipTest('clang required')
        cls.build_dir = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.build_dir.cleanup)
        cls.executable = Path(cls.build_dir.name) / 'backup-probe'
        result = subprocess.run([compiler, '-std=gnu11', '-fobjc-arc', '-Wall', '-Wextra', '-Werror',
                                 str(ROOT / 'tests/cheat_backup_probe.m'),
                                 str(ROOT / 'games/totk/runtime/cheat_backup.m'),
                                 str(ROOT / 'games/totk/runtime/game_slot.c'),
                                 '-framework', 'Foundation', '-o', str(cls.executable)],
                                capture_output=True, text=True)
        if result.returncode:
            raise AssertionError(result.stderr)

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.profile = self.root / 'profile'
        self.profile.mkdir()
        (self.profile / 'save').mkdir()
        (self.profile / 'save/progress.sav').write_bytes(b'synthetic original')
        self.data = self.root / 'game-data'
        self.data.mkdir()
        self.slot = self.root / 'slot'
        self.slot.mkdir()
        self.env = dict(os.environ, TOTK_PROFILE_DIR=str(self.profile), TEST_GAME_DATA=str(self.data),
                        TOTK_GAME_SLOT_DIR=str(self.slot), TOTK_GAME_SLOT_WAIT='0',
                        TOTK_GAME_SLOT_TEST_IGNORE_LEGACY='1', TOTK_SLOT_OWNER='test', TOTK_SLOT_PURPOSE='backup-test')
        for key in ('TOTK_GAME_SLOT_FD', 'TOTK_SLOT_TOKEN', 'TOTK_GAME_SLOT_DRYRUN'):
            self.env.pop(key, None)

    def record(self, fingerprint='a' * 64):
        (self.data / 'cheats-selection.json').write_text(json.dumps({'patch_sha256': fingerprint}))

    def invoke(self):
        return subprocess.run([str(self.executable)], env=self.env, capture_output=True, text=True, timeout=10)

    def test_complete_backup_once_per_selection(self):
        self.record()
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        backup = self.root / ('profile-before-cheats-' + 'a' * 16)
        self.assertEqual((backup / 'save/progress.sav').read_bytes(), b'synthetic original')
        (self.profile / 'save/progress.sav').write_bytes(b'new progress')
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((backup / 'save/progress.sav').read_bytes(), b'synthetic original')
        self.record('b' * 64)
        self.assertEqual(self.invoke().returncode, 0)
        other = self.root / ('profile-before-cheats-' + 'b' * 16)
        self.assertEqual((other / 'save/progress.sav').read_bytes(), b'new progress')
        self.assertFalse(list(self.root.glob('*.copy-*')))

    def test_busy_game_or_migration_cannot_be_backed_up(self):
        self.record()
        with (self.slot / 'lock').open('w') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            result = self.invoke()
            self.assertEqual(result.returncode, 75, result.stderr)
        self.assertFalse(list(self.root.glob('profile-before-cheats-*')))
        self.assertEqual((self.profile / 'save/progress.sav').read_bytes(), b'synthetic original')

    def test_invalid_record_prevents_startup(self):
        for value in ('not-a-hash', 42, '../' + 'a' * 61):
            self.record(value)
            result = self.invoke()
            self.assertEqual(result.returncode, 2, result.stderr)
        self.assertFalse(list(self.root.glob('profile-before-cheats-*')))

    def test_existing_file_or_symlink_cannot_impersonate_a_backup(self):
        self.record()
        backup = self.root / ('profile-before-cheats-' + 'a' * 16)
        backup.write_bytes(b'unrelated file')
        self.assertEqual(self.invoke().returncode, 2)
        self.assertEqual(backup.read_bytes(), b'unrelated file')
        backup.unlink()
        backup.symlink_to(self.profile, target_is_directory=True)
        self.assertEqual(self.invoke().returncode, 2)
        self.assertTrue(backup.is_symlink())

    def test_plain_build_and_new_profile_do_not_create_backups(self):
        self.assertEqual(self.invoke().returncode, 0)
        self.assertFalse(list(self.root.glob('profile-before-cheats-*')))
        self.record()
        shutil.rmtree(self.profile)
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(list(self.root.glob('profile-before-cheats-*')))


if __name__ == '__main__':
    unittest.main()
