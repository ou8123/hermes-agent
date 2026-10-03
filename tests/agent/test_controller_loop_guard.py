"""Regression tests for controller loop gaps A-E (terminal loops, pathless search
identity, non-fatal narrowing, missing call IDs, stop diagnostics)."""
import concurrent.futures
import json
import os
import pathlib
import stat
import tempfile
import unittest

from agent.controller_loop_guard import ControllerLoopGuard, classify, failed_locations, call_signature


def term(output='', exit_code=0, error=None):
    return json.dumps({'output': output, 'exit_code': exit_code, 'error': error, 'status': 'ok' if exit_code == 0 else 'error'})


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.home = pathlib.Path(self.tmp.name).resolve()
        self.guard = ControllerLoopGuard({}, self.home / 'artifacts/controller-evidence/run_x', profile_home=self.home)
        self.calls = []

    def run_tool(self, tool, args, result, call_id='auto'):
        if call_id == 'auto':
            self.n = getattr(self, 'n', 0) + 1; call_id = 'call_%d' % self.n
        def cb(a):
            self.calls.append((tool, a)); return result
        return self.guard.execute(tool, args, call_id, cb)

    def sh(self, command, result, call_id='auto', **extra):
        return self.run_tool('terminal', dict(command=command, **extra), result, call_id)

    def blocked(self, result):
        return ControllerLoopGuard.is_blocked(result) and json.loads(result)


class GapA_TerminalLoops(Base):
    def test_missing_file_cat_is_not_retried_and_fences_location_across_tools(self):
        missing = term('cat: /data/nope.txt: No such file or directory', 1)
        self.sh('cat /data/nope.txt', missing)
        again = self.blocked(self.sh('cat  /data/nope.txt', 'NEVER'))  # whitespace-normalized twin
        self.assertEqual(again['error'], 'REPEATED_INEFFECTIVE_ACTION')
        self.assertEqual(again['category'], 'not_found')
        # Same missing location through other read-only tools / the search tool.
        self.assertEqual(self.blocked(self.sh('head -5 /data/nope.txt', 'NEVER'))['error'], 'LOCATION_FENCED')
        self.assertEqual(len(self.calls), 1)
        self.assertIsNone(self.guard.stop_reason)

    def test_permission_denied_grep_cannot_be_bypassed_with_find_rg_or_search_files(self):
        self.sh('grep -r token /root/secret', term('grep: /root/secret: Permission denied', 2))
        self.assertEqual(self.blocked(self.sh('find /root/secret -name x', 'NEVER'))['error'], 'LOCATION_FENCED')
        # A useful alternative succeeds and resets the consecutive-block counter.
        self.assertEqual(self.sh('ls /opt/allowed', term('a b')), term('a b'))
        self.assertEqual(self.blocked(self.sh('rg token /root/secret', 'NEVER'))['error'], 'LOCATION_FENCED')
        self.assertEqual(self.blocked(self.run_tool('search_files', {'path': '/root/secret', 'pattern': 'x'}, 'NEVER'))['error'], 'LOCATION_FENCED')
        self.assertIsNone(self.guard.stop_reason)
        self.assertEqual([c[1].get('command') for c in self.calls], ['grep -r token /root/secret', 'ls /opt/allowed'])

    def test_search_tool_denial_also_fences_terminal_reads(self):
        self.run_tool('search_files', {'path': '/srv/private', 'pattern': 'a'}, '{"error":"Permission denied"}')
        self.assertEqual(self.blocked(self.sh('grep -r a /srv/private', 'NEVER'))['category'], 'permission_denied')
        # Narrowing into a specific child of a denied directory stays allowed.
        self.assertEqual(self.sh('cat /srv/private/readme.txt', term('hi')), term('hi'))

    def test_permission_denied_fence_does_not_cover_siblings_or_children_writes(self):
        self.sh('cat /etc/shadow', term('cat: /etc/shadow: Permission denied', 1))
        self.assertEqual(self.sh('cat /etc/hostname', term('box')), term('box'))

    def test_missing_dependency_python_retry_blocked_until_state_changes(self):
        fail = term('Traceback...\nModuleNotFoundError: No module named \'dotenv\'', 1)
        self.sh('python3 tools/report.py', fail)
        self.assertEqual(self.blocked(self.sh('python3 tools/report.py', 'NEVER'))['category'], 'missing_dependency')
        # Materially different command is allowed and changes state.
        self.sh('/opt/hermes/.venv/bin/python -m pip install python-dotenv', term('Successfully installed'))
        self.assertEqual(self.sh('python3 tools/report.py', term('report ok')), term('report ok'))

    def test_generic_failure_identical_twice_then_blocked(self):
        boom = term('assertion failed: x', 1)
        self.sh('make check', boom); self.sh('make check', boom)
        self.assertEqual(self.blocked(self.sh('make check', 'NEVER'))['error'], 'REPEATED_INEFFECTIVE_ACTION')

    def test_generic_failure_with_changed_output_is_progress(self):
        self.sh('pytest -x', term('1 failed', 1)); self.sh('pytest -x', term('2 failed', 1))
        self.assertEqual(self.sh('pytest -x', term('3 failed', 1)), term('3 failed', 1))

    def test_unchanged_repeated_grep_is_exhausted_but_changed_grep_allowed(self):
        same = term('a.py:1:foo')
        for _ in range(3): self.sh('grep -rn foo src', same)
        self.assertEqual(self.blocked(self.sh('grep -rn foo src', 'NEVER'))['error'], 'REPEATED_INEFFECTIVE_ACTION')
        self.assertEqual(self.sh('grep -rn foo tests', term('t.py:2:foo')), term('t.py:2:foo'))

    def test_large_terminal_grep_output_is_capped_with_private_evidence(self):
        result = self.sh('grep -rn x /var/log', term('x' * 50000))
        data = json.loads(result)
        self.assertTrue(data['truncated']); self.assertLessEqual(len(result.encode()), 8192)
        evidence = pathlib.Path(data['evidence_path'])
        self.assertTrue(evidence.exists()); self.assertEqual(stat.S_IMODE(evidence.stat().st_mode), 0o600)

    def test_failed_location_parser(self):
        locs = failed_locations(term("python3: can't open file '/w/run.py': [Errno 2] No such file or directory\n"
                                     "PermissionError: [Errno 13] Permission denied: '/w/secret.env'", 1))
        self.assertEqual(locs, {'/w/run.py': 'not_found', '/w/secret.env': 'permission_denied'})
        self.assertEqual(classify('terminal', term('bash: rgx: command not found', 127)), (True, 'missing_dependency'))
        self.assertEqual(classify('terminal', term('hello', 0)), (False, None))


class GapB_PathlessSearchIdentity(Base):
    def test_default_path_searches_do_not_poison_each_other(self):
        self.run_tool('search_files', {'pattern': 'alpha'}, '{"error":"No such file or directory"}')
        self.assertEqual(self.run_tool('search_files', {'pattern': 'beta'}, '{"matches":["x"]}'), '{"matches":["x"]}')
        self.assertEqual(self.run_tool('search_files', {'pattern': 'gamma', 'path': '.'}, '{"matches":["y"]}'), '{"matches":["y"]}')
        self.assertEqual(self.blocked(self.run_tool('search_files', {'pattern': 'alpha'}, 'NEVER'))['error'], 'REPEATED_INEFFECTIVE_ACTION')

    def test_identity_includes_pagination_and_filters(self):
        base = {'path': '/repo', 'pattern': 'x'}
        sigs = {call_signature('search_files', dict(base, offset=o, file_glob=g)) for o in (0, 50) for g in ('*.py', '*.js')}
        self.assertEqual(len(sigs), 4)

    def test_legitimate_pagination_is_not_a_loop(self):
        for page, offset in enumerate(range(0, 300, 50)):
            r = self.run_tool('search_files', {'path': '/repo', 'pattern': 'TODO', 'offset': offset}, '{"matches":["p%d"]}' % page, 'p%d' % page)
            self.assertFalse(ControllerLoopGuard.is_blocked(r))
        self.assertIsNone(self.guard.stop_reason)


class GapC_NarrowNotKill(Base):
    def test_block_returns_structured_refusal_and_run_continues(self):
        self.sh('cat /x/missing', term('cat: /x/missing: No such file or directory', 1))
        refusal = self.blocked(self.sh('cat /x/missing', 'NEVER'))
        self.assertTrue(refusal['run_continues'])
        self.assertIn('guidance', refusal)
        self.assertIsNone(self.guard.stop_reason)
        self.assertEqual(self.sh('ls /x', term('present.txt')), term('present.txt'))  # worker proceeds

    def test_three_consecutive_blocked_choices_stop_the_run_as_a_loop(self):
        self.sh('cat /x/missing', term('cat: /x/missing: No such file or directory', 1))
        for _ in range(3): self.sh('cat /x/missing', 'NEVER')
        self.assertEqual(self.guard.stop_reason, 'REPEATED_BLOCKED_ACTIONS')
        self.assertEqual(self.guard.stop_detail['kind'], 'repeated_equivalent_action')
        refusal = self.blocked(self.sh('ls /x', 'NEVER'))
        self.assertFalse(refusal['run_continues'])

    def test_saved_artifact_regeneration_is_refused_without_killing_the_job(self):
        import hashlib
        art = self.home / 'artifacts' / 'img.png'; art.parent.mkdir(parents=True, exist_ok=True); art.write_bytes(b'img')
        g = ControllerLoopGuard({'saved_artifact': {'path': str(art), 'sha256': hashlib.sha256(b'img').hexdigest(), 'source_job_id': 'j'}},
                                self.home / 'artifacts/controller-evidence/r', profile_home=self.home)
        r = g.execute('image_generate', {'prompt': 'again'}, 'a', lambda _: 'NEVER')
        self.assertEqual(json.loads(r)['error'], 'SAVED_ARTIFACT_REGENERATION_FORBIDDEN')
        self.assertIsNone(g.stop_reason)
        self.assertEqual(g.execute('read_file', {'path': str(art)}, 'b', lambda _: 'bytes'), 'bytes')


class GapD_MissingCallIds(Base):
    def test_empty_and_none_ids_never_collide(self):
        for i in range(10):
            cid = '' if i % 2 else None
            self.assertEqual(self.run_tool('read_file', {'path': '/f%d' % i}, 'ok%d' % i, cid), 'ok%d' % i)
        self.assertEqual(len(self.calls), 10)
        self.assertIsNone(self.guard.stop_reason)

    def test_parallel_empty_ids_are_counted_individually(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            out = list(pool.map(lambda i: self.run_tool('read_file', {'path': '/p%d' % i}, 'ok', ''), range(8)))
        self.assertEqual(out, ['ok'] * 8)
        self.assertEqual(self.guard.attempts, 8); self.assertEqual(len(self.guard.dispatched), 8)

    def test_executor_ticket_flow_with_empty_ids(self):
        tickets = [self.guard.new_ticket('') for _ in range(3)]
        self.assertEqual(len(set(tickets)), 3)
        for i, t in enumerate(tickets):
            self.assertIsNone(self.guard.admit('read_file', {'path': '/t%d' % i}, t))
            self.assertEqual(self.guard.execute_admitted('read_file', {'path': '/t%d' % i}, t, lambda _: 'ok'), 'ok')

    def test_repeated_nonempty_provider_id_does_not_repeat_side_effect_or_stop(self):
        self.run_tool('write_file', {'path': '/a', 'content': '1'}, 'ok', 'call_1')
        dup = self.blocked(self.run_tool('write_file', {'path': '/a', 'content': '1'}, 'NEVER', 'call_1'))
        self.assertEqual(dup['error'], 'DUPLICATE_TOOL_CALL_ID')
        self.assertIsNone(self.guard.stop_reason)
        self.assertEqual(len(self.calls), 1)

    def test_forty_calls_with_missing_ids_hit_only_the_budget(self):
        for i in range(40): self.run_tool('read_file', {'path': '/b%d' % i}, 'ok', None)
        self.assertIsNone(self.guard.stop_reason)
        self.assertTrue(self.blocked(self.run_tool('read_file', {'path': '/b40'}, 'NEVER', None)))
        self.assertEqual(self.guard.stop_reason, 'TOOL_LOOP_LIMIT')
        self.assertEqual(len(self.calls), 40)


class GapE_Diagnostics(Base):
    def test_budget_stop_reports_count_limit_trigger_and_kind_without_secrets(self):
        for i in range(40): self.sh('echo step %d' % i, term('step'), 'id%d' % i)
        self.sh('curl -H "Authorization: Bearer sk-live-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" https://x', 'NEVER', 'last')
        d = self.guard.stop_detail
        self.assertEqual((d['stop_reason'], d['kind'], d['count'], d['limit']), ('TOOL_LOOP_LIMIT', 'global_budget', 41, 40))
        self.assertEqual(d['trigger']['tool'], 'terminal')
        self.assertEqual(len(d['trigger']['signature']), 16)
        self.assertNotIn('ABCDEFGHIJKLMNOP', json.dumps(d))
        summary = self.guard.evidence_dir / 'loop-guard-summary.json'
        self.assertEqual(stat.S_IMODE(summary.stat().st_mode), 0o600)
        on_disk = json.loads(summary.read_text())
        self.assertEqual(on_disk['stop']['stop_reason'], 'TOOL_LOOP_LIMIT')
        self.assertNotIn('ABCDEFGHIJKLMNOP', summary.read_text())
        self.assertLess(len(summary.read_text()), 8192)

    def test_repeat_stop_reports_signature_and_category(self):
        self.sh('cat /m/x', term('cat: /m/x: No such file or directory', 1))
        for _ in range(3): self.sh('cat /m/x', 'NEVER')
        d = self.guard.stop_detail
        self.assertEqual(d['kind'], 'repeated_equivalent_action')
        self.assertEqual(d['trigger']['category'], 'not_found')
        self.assertIn('cat /m/x', d['trigger']['preview'])



if __name__ == '__main__':
    unittest.main()
