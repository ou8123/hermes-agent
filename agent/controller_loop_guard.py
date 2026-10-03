"""Restrictive, run-local execution policy. Never grants tools or approvals."""
import hashlib
import contextvars
import json
import os
import pathlib
import re
import stat
import threading

SEARCH_TOOLS = {'search_files', 'session_search'}
MAX_RESULT_BYTES = 8192
_active_guard = contextvars.ContextVar('hermes_controller_loop_guard', default=None)


def has_active_guard():
    return _active_guard.get() is not None


def current_effect_error(paths=()):
    """Optional run-local check after tool-internal approval, before mutation."""
    guard = _active_guard.get()
    if guard is None:
        return None
    reason = guard.cancellation_fence()
    if reason:
        return reason
    if guard.saved_artifact:
        try:
            saved = verify_saved_artifact(guard.saved_artifact, guard.profile_home)
            for path in paths:
                candidate = pathlib.Path(path).resolve()
                if candidate == saved or (candidate.exists() and candidate.samefile(saved)):
                    guard.stop_reason = 'SAVED_ARTIFACT_OVERWRITE_FORBIDDEN'
                    return guard.stop_reason
        except (OSError, ValueError, TypeError):
            guard.stop_reason = 'SAVED_ARTIFACT_CHANGED_OR_UNVERIFIED'
            return guard.stop_reason
    return None


class BlockedResult(str):
    """A tool was fenced before its callback; audit as blocked, not dispatched."""


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def error_category(result):
    # Inspect the current result, not quoted historical text inside a hit.
    try:
        data = json.loads(result)
    except (ValueError, TypeError):
        data = None
    if isinstance(data, dict):
        error = data.get('error')
        if not error:
            return None
        text = str(error)
    else:
        text = data if isinstance(data, str) else str(result)
        if not re.match(r'(?is)^\s*(?:error|traceback|permission denied|no such file|filenotfounderror)', text):
            return None
    if re.search(r'permission.?denied|PermissionError', text, re.I):
        return 'permission_denied'
    if re.search(r'not found|no such file|does not exist|FileNotFoundError', text, re.I):
        return 'not_found'
    return None


def resource_key(tool, args):
    # Query/pattern/pagination changes cannot escape a denied resource fence.
    values = [args[k] for k in ('path', 'directory', 'root', 'file_path', 'session_id')
              if isinstance(args.get(k), str) and args[k]]
    # Extra ignored argument aliases cannot change the actual resource key.
    values = values[:1]
    if not values and isinstance(args.get('target'), str) and args['target'].startswith(('/', './', '../')):
        values = [args['target']]
    return tool + ':' + json.dumps([os.path.normpath(v) for v in values], sort_keys=True)


def empty_search_result(text):
    try:
        value = json.loads(text)
    except ValueError:
        return bool(re.match(r'(?is)^\s*no (?:matches|results|sessions) found\s*[.!]?\s*$', text))
    if not isinstance(value, dict) or value.get('error'):
        return False
    if any(value.get(key) == 0 for key in ('total_count', 'total_matches') if key in value):
        return True
    return any(value.get(key) == [] for key in ('matches', 'results', 'hits', 'sessions') if key in value)


def open_directory(root, parts, create=False):
    """Walk with anchored directory FDs: no parent/leaf symlink following."""
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    fd = os.open(root, flags)
    try:
        for part in parts:
            if part in ('', '.', '..') or '/' in part:
                raise ValueError('invalid confined path component')
            if create:
                try:
                    os.mkdir(part, 0o700, dir_fd=fd)
                except FileExistsError:
                    pass
            child = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def verify_saved_artifact(saved, profile_home):
    if not isinstance(saved, dict) or set(saved) != {'path', 'sha256', 'source_job_id'}:
        raise ValueError('invalid saved artifact reference')
    home = pathlib.Path(profile_home).resolve()
    path = pathlib.Path(saved['path']).resolve(strict=True)
    allowed = (home / 'artifacts').resolve()
    if not allowed.is_relative_to(home) or not path.is_relative_to(allowed) or not path.is_file():
        raise ValueError('saved artifact outside this profile artifacts')
    relative = path.relative_to(home)
    directory = open_directory(home, relative.parts[:-1])
    try:
        fd = os.open(relative.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
        with os.fdopen(fd, 'rb') as source:
            before = os.fstat(source.fileno())
            if not stat.S_ISREG(before.st_mode):
                raise ValueError('saved artifact is not a regular file')
            data = source.read(32 * 1024 * 1024 + 1)
            after = os.fstat(source.fileno())
        if len(data) > 32 * 1024 * 1024:
            raise ValueError('saved artifact exceeds verification size bound')
        if (before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_ino, after.st_size, after.st_mtime_ns):
            raise ValueError('saved artifact changed during verification')
        if hashlib.sha256(data).hexdigest() != saved['sha256']:
            raise ValueError('saved artifact hash mismatch')
    finally:
        os.close(directory)
    return path



# ---- normalization / classification (gaps A, B) -------------------------
POLLING_TOOLS = {'process', 'read_terminal', 'todo', 'clarify', 'memory'}
MUTATING_TOOLS = {'write_file', 'patch', 'edit_file', 'execute_code', 'image_generate',
                  'skill_manage', 'delegate_task', 'close_terminal'}
READ_ONLY_COMMANDS = {'grep', 'egrep', 'fgrep', 'rg', 'ag', 'find', 'fd', 'locate', 'cat', 'less',
                      'more', 'head', 'tail', 'ls', 'tree', 'stat', 'file', 'wc', 'du', 'df', 'pwd',
                      'which', 'whereis', 'type', 'echo', 'printf', 'readlink', 'realpath', 'id',
                      'whoami', 'date', 'env', 'printenv', 'sha256sum', 'md5sum', 'diff', 'cmp'}
SEARCH_COMMANDS = {'grep', 'egrep', 'fgrep', 'rg', 'ag', 'find', 'fd', 'locate', 'ls', 'tree'}
REPEAT_SUCCESS_LIMIT = 3      # identical successful outcomes before the signature is exhausted
MAX_CONSECUTIVE_BLOCKS = 3    # blocked attempts in a row = demonstrated loop -> stop the run
_SECRETISH = re.compile(r'(?i)((?:token|secret|password|passwd|api[_-]?key|authorization|bearer|cookie)'
                        r'[\w-]*\s*[=:]\s*|bearer\s+)\S+')
_LONG_OPAQUE = re.compile(r'[A-Za-z0-9_\-]{32,}')
_PATH_ERRORS = [
    # coreutils / grep / find / rg / sed / python file errors
    re.compile(r"(?m)(?:^|[\s:])[\w.\-]*:?\s*(?:cannot (?:access|open|stat)\s+)?['\"‘`]?((?:/|\./|\.\./|~/)[^\s'\"’`:]+)['\"’`]?:\s*(No such file or directory|Permission denied)"),
    re.compile(r"(?:PermissionError|FileNotFoundError|IsADirectoryError|NotADirectoryError): \[Errno \d+\] [^:\n]+: '([^']+)'"),
    re.compile(r"can't open file '([^']+)': \[Errno (\d+)\]"),
]


def redact_preview(text, limit=160):
    text = _SECRETISH.sub(lambda m: m.group(1) + '[REDACTED]', str(text))
    text = _LONG_OPAQUE.sub('[OPAQUE]', text)
    text = ' '.join(text.split())
    return text if len(text) <= limit else text[:limit - 1] + '…'


def _norm_path(value, base=None):
    if not isinstance(value, str) or not value:
        return None
    value = os.path.expanduser(value)
    if not os.path.isabs(value) and base:
        value = os.path.join(base, value)
    return os.path.normpath(value)


def command_words(command):
    import shlex
    try:
        return shlex.split(command, comments=False, posix=True)
    except ValueError:
        return command.split()


def command_head(command):
    """First program of a (possibly env/sudo/timeout-prefixed) command."""
    for word in command_words(command):
        if '=' in word and not word.startswith(('/', '.')) and word.split('=', 1)[0].isidentifier():
            continue
        if word in ('sudo', 'env', 'timeout', 'nice', 'nohup', 'time', 'command', 'exec'):
            continue
        return os.path.basename(word)
    return ''


def command_paths(command, workdir=None):
    """Explicit path-like operands of a command (for location fences)."""
    out = []
    for word in command_words(command):
        if word.startswith('-') and '=' in word:
            word = word.split('=', 1)[1]
        if word.startswith(('/', './', '../', '~/')):
            norm = _norm_path(word, workdir)
            if norm:
                out.append(norm)
    return out


def call_signature(tool, args):
    """Normalized identity of an action. Every meaningful argument is part of it
    (path + pattern + filters + pagination), so unrelated default-path searches
    never share an identity (gap B)."""
    args = args if isinstance(args, dict) else {}
    if tool == 'terminal':
        workdir = _norm_path(args.get('workdir')) or ''
        command = ' '.join(str(args.get('command', '')).split())
        return 'terminal:' + json.dumps([command, workdir, bool(args.get('background'))])
    norm = dict(args)
    for key in ('path', 'directory', 'root', 'file_path'):
        if isinstance(norm.get(key), str) and norm[key]:
            norm[key] = os.path.normpath(norm[key])
    if tool == 'search_files':
        norm.setdefault('path', '.')
    return tool + ':' + json.dumps(norm, sort_keys=True, default=str)


def explicit_search_location(tool, args):
    """A search fences a *location* only when the caller named one."""
    if tool != 'search_files' or not isinstance(args, dict):
        return None
    for key in ('path', 'directory', 'root'):
        value = args.get(key)
        if isinstance(value, str) and value and os.path.normpath(value) != '.':
            return _norm_path(value)
    return None


def inflight_key(tool, args):
    location = explicit_search_location(tool, args)
    return ('loc:' + location) if location else call_signature(tool, args)


def classify(tool, result_text):
    """(failed, category) for one tool result. Categories are deterministic
    failures that retrying unchanged cannot fix."""
    try:
        data = json.loads(result_text)
    except (ValueError, TypeError):
        data = None
    failed = False
    text = ''
    if isinstance(data, dict):
        code = data.get('exit_code')
        error = data.get('error')
        if error or (isinstance(code, int) and code not in (0,)):
            failed = True
        text = ' '.join(str(x) for x in (error or '', str(data.get('output', ''))[-4096:]))
    else:
        text = str(result_text)
        failed = bool(re.match(r'(?is)^\s*(?:error|traceback|permission denied|no such file|filenotfounderror)', text))
    if not failed:
        return False, None
    if re.search(r'command not found|ModuleNotFoundError|No module named|ImportError|executable file not found|'
                 r'cannot find module|is not installed|not recognized as an internal', text, re.I):
        return True, 'missing_dependency'
    if re.search(r'permission.?denied|PermissionError|EACCES|Operation not permitted', text, re.I):
        return True, 'permission_denied'
    if re.search(r'not found|no such file|does not exist|FileNotFoundError|ENOENT', text, re.I):
        return True, 'not_found'
    return True, 'failed'


def failed_locations(result_text, workdir=None):
    try:
        data = json.loads(result_text)
        text = ' '.join(str(data.get(k, '')) for k in ('error', 'output')) if isinstance(data, dict) else str(result_text)
    except (ValueError, TypeError):
        text = str(result_text)
    found = {}
    for pattern in _PATH_ERRORS:
        for m in pattern.finditer(text):
            path = _norm_path(m.group(1), workdir)
            reason = m.group(2) if m.lastindex and m.lastindex >= 2 else ''
            if not path:
                continue
            if 'ermission' in reason or 'PermissionError' in m.group(0) or reason == '13':
                found[path] = 'permission_denied'
            else:
                found.setdefault(path, 'not_found')
    return found


def outcome_digest(result_text):
    text = str(result_text)
    try:
        data = json.loads(text)
        if isinstance(data, dict):
            # Durations/timestamps are noise, not progress.
            data = {k: v for k, v in data.items() if k not in ('duration', 'elapsed', 'timestamp', 'took_ms')}
            text = json.dumps(data, sort_keys=True)
    except (ValueError, TypeError):
        pass
    return digest(text)


class ControllerLoopGuard:
    """Run-local loop policy. Blocks ineffective actions (structured refusal,
    run continues) and stops the run only on budget exhaustion, a demonstrated
    loop of blocked attempts, cancellation or a nonrecoverable artifact breach."""

    def __init__(self, policy, evidence_dir, cancelled=lambda: False, profile_home=None):
        if not isinstance(policy, dict) or set(policy) - {'max_tools', 'saved_artifact'}:
            raise ValueError('invalid restrictive controller loop policy')
        self.max_tools = policy.get('max_tools', 40)
        if type(self.max_tools) is not int or not 1 <= self.max_tools <= 40:
            raise ValueError('controller tool ceiling must be 1..40')
        self.evidence_dir = pathlib.Path(evidence_dir).resolve()
        self.profile_home = pathlib.Path(profile_home).resolve() if profile_home else self.evidence_dir.parent
        self.evidence_parts = self.evidence_dir.relative_to(self.profile_home).parts
        self.cancelled = cancelled
        self.lock = threading.RLock()
        self.saved_artifact = policy.get('saved_artifact')
        self.stop_reason = None
        self.stop_detail = None
        self._seq = 0
        self.attempts = 0                # every tool call the model asked for (budgeted)
        self.admitted = set()            # tickets allowed to dispatch
        self.dispatched = set()
        self.blocked = 0
        self.consecutive_blocked = 0
        self.epoch = 0                   # bumps on successful state-changing actions
        self.signature_fences = {}       # sig -> (reason, category, epoch)
        self.location_fences = {}        # path -> (category, epoch)
        self.outcomes = {}               # sig -> (epoch, digest, repeat_count)
        self.inflight_resources = {}     # search sig -> ticket
        self.tickets = {}                # ticket -> (tool, sig, call_id)
        self.recent = []                 # bounded audit trail for diagnostics
        self.failures = self.location_fences  # backward-compatible alias
        self._by_call = {}               # raw tool_call_id -> latest ticket (legacy callers)
        self._tls = threading.local()    # per-thread latest ticket (legacy callers, empty ids)
        self._ticket_call = {}           # ticket -> raw provider tool_call_id (metadata)
        self._seen_calls = set()         # non-empty provider ids already dispatched/admitted

    # ---- identity (gap D) ------------------------------------------------
    def new_ticket(self, call_id=None):
        """Per-invocation identity. The model's tool_call_id is metadata only:
        empty or repeated IDs never collide or stop the run."""
        with self.lock:
            self._seq += 1
            ticket = '%d:%s' % (self._seq, call_id or '-')
            self._ticket_call[ticket] = call_id or None
            return ticket

    def _ticket(self, call_id):
        # Tickets issued by new_ticket() pass through; a raw tool_call_id
        # (legacy caller) gets a fresh ticket so empty/duplicate IDs never collide.
        if isinstance(call_id, str) and re.match(r'^\d+:', call_id) and call_id not in self.tickets:
            return call_id
        return self.new_ticket(call_id)

    def _resolve_ticket(self, call_id):
        if call_id in self.tickets:
            return call_id
        if call_id and call_id in self._by_call:
            return self._by_call[call_id]
        return getattr(self._tls, 'ticket', None)

    # ---- diagnostics (gap E) --------------------------------------------
    def _note(self, kind, tool, sig, **extra):
        entry = {'n': self.attempts, 'kind': kind, 'tool': tool,
                 'signature': digest(sig)[:16], 'preview': redact_preview(sig.split(':', 1)[1] if ':' in sig else sig)}
        entry.update({k: v for k, v in extra.items() if v is not None})
        self.recent = (self.recent + [entry])[-8:]
        return entry

    def _stop(self, reason, kind, tool=None, sig=None, category=None):
        if self.stop_reason:
            return self.stop_reason
        self.stop_reason = reason
        self.stop_detail = {
            'stop_reason': reason, 'kind': kind,
            'count': self.attempts, 'limit': self.max_tools,
            'dispatched': len(self.dispatched), 'blocked': self.blocked,
            'trigger': None if tool is None else {
                'tool': tool, 'signature': digest(sig or '')[:16],
                'preview': redact_preview((sig or '').split(':', 1)[-1]), 'category': category},
        }
        self.write_summary()
        return reason

    def diagnostics(self):
        with self.lock:
            return {'schema': 'hermes-controller-loop-guard/1', 'stop': self.stop_detail,
                    'attempts': self.attempts, 'limit': self.max_tools,
                    'dispatched': len(self.dispatched), 'blocked': self.blocked,
                    'epoch': self.epoch, 'fenced_signatures': len(self.signature_fences),
                    'fenced_locations': sorted(self.location_fences)[:20], 'recent': list(self.recent)}

    def write_summary(self):
        try:
            payload = json.dumps(self.diagnostics(), indent=2).encode()
            directory = open_directory(self.profile_home, self.evidence_parts, create=True)
            try:
                tmp = 'loop-guard-summary.json.tmp'
                fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600, dir_fd=directory)
                with os.fdopen(fd, 'wb') as out:
                    out.write(payload)
                os.replace(tmp, 'loop-guard-summary.json', src_dir_fd=directory, dst_dir_fd=directory)
            finally:
                os.close(directory)
        except (OSError, ValueError):
            pass  # diagnostics must never change tool behavior

    def blocked_payload(self, reason):
        with self.lock:
            detail = self.recent[-1] if self.recent else {}
            fatal = bool(self.stop_reason)
            guidance = {
                'REPEATED_INEFFECTIVE_ACTION': 'This exact action already failed or returned the same result. Change the command, path, arguments or state before retrying.',
                'LOCATION_FENCED': 'This location already returned permission-denied or not-found. Use a different, narrower or verified path, or report the blocker.',
                'SEARCH_RESOURCE_IN_FLIGHT': 'A search of this location is already running; use its result before searching it again.',
                'DUPLICATE_TOOL_CALL_ID': 'This tool call was already executed; its side effect is not repeated.',
                'SAVED_ARTIFACT_REGENERATION_FORBIDDEN': 'Use the verified saved artifact; do not regenerate it.',
                'SAVED_ARTIFACT_OVERWRITE_FORBIDDEN': 'The verified saved artifact is read-only for this job.',
            }.get(reason, 'Run stopped by controller loop policy.' if fatal else 'Action blocked by controller loop policy.')
            return json.dumps({'error': reason, 'controller_loop_blocked': True, 'run_continues': not fatal,
                               'guidance': guidance, 'signature': detail.get('signature'),
                               'action': detail.get('preview'), 'category': detail.get('category'),
                               'tool_calls_used': self.attempts, 'tool_call_limit': self.max_tools})

    # ---- admission ------------------------------------------------------
    def _block(self, reason, tool, sig, category=None, transient=False):
        self.blocked += 1
        if transient:
            # Waiting for an in-flight twin is not a model loop.
            self._note('blocked', tool, sig, reason=reason, category=category)
            return reason
        self.consecutive_blocked += 1
        self._note('blocked', tool, sig, reason=reason, category=category)
        if self.consecutive_blocked >= MAX_CONSECUTIVE_BLOCKS:
            # Repeatedly choosing fenced actions is a demonstrated loop.
            self._stop('REPEATED_BLOCKED_ACTIONS', 'repeated_equivalent_action', tool, sig, category)
            return self.stop_reason
        self.write_summary()
        return reason

    def _location_hit(self, paths):
        for path in paths:
            for fenced, (category, epoch) in self.location_fences.items():
                if epoch != self.epoch:
                    continue
                # Children of a missing location are missing too; children of a
                # denied directory may be readable, so narrowing into them is allowed.
                if path == fenced or (category == 'not_found' and path.startswith(fenced.rstrip('/') + '/')):
                    return fenced, category
        return None

    def admit(self, tool, args, call_id, resolve_path=None):
        with self.lock:
            if self.cancelled():
                return 'USER_CANCEL'
            if self.stop_reason:
                return self.stop_reason
            ticket = self._ticket(call_id)
            raw_id = self._ticket_call.get(ticket, call_id if call_id != ticket else None)
            sig = call_signature(tool, args)
            self.attempts += 1
            if raw_id and raw_id in self._seen_calls:
                # Same provider call delivered twice: never repeat its side
                # effect, but do not stop the run (gap D).
                return self._block('DUPLICATE_TOOL_CALL_ID', tool, sig, transient=True)
            if self.attempts > self.max_tools:
                self._note('blocked', tool, sig, reason='TOOL_LOOP_LIMIT')
                return self._stop('TOOL_LOOP_LIMIT', 'global_budget', tool, sig)
            if self.saved_artifact:
                try:
                    verify_saved_artifact(self.saved_artifact, self.profile_home)
                except (OSError, ValueError, TypeError):
                    return self._stop('SAVED_ARTIFACT_CHANGED_OR_UNVERIFIED', 'nonrecoverable', tool, sig)
                if tool == 'image_generate':
                    return self._block('SAVED_ARTIFACT_REGENERATION_FORBIDDEN', tool, sig)
                if tool in {'write_file', 'edit_file', 'patch'}:
                    destination = args.get('path') or args.get('file_path')
                    resolved = resolve_path(destination) if destination and resolve_path else destination
                    if resolved and pathlib.Path(resolved).resolve() == pathlib.Path(self.saved_artifact['path']).resolve():
                        return self._block('SAVED_ARTIFACT_OVERWRITE_FORBIDDEN', tool, sig)
            fence = self.signature_fences.get(sig)
            if fence and fence[2] == self.epoch:
                return self._block('REPEATED_INEFFECTIVE_ACTION', tool, sig, fence[1])
            if tool == 'terminal':
                command = str(args.get('command', ''))
                if command_head(command) in READ_ONLY_COMMANDS:
                    hit = self._location_hit(command_paths(command, _norm_path(args.get('workdir'))))
                    if hit:
                        return self._block('LOCATION_FENCED', tool, sig, hit[1])
            location = explicit_search_location(tool, args)
            if location:
                hit = self._location_hit([location])
                if hit:
                    return self._block('LOCATION_FENCED', tool, sig, hit[1])
            if tool in SEARCH_TOOLS:
                key = inflight_key(tool, args)
                if key in self.inflight_resources:
                    return self._block('SEARCH_RESOURCE_IN_FLIGHT', tool, sig, transient=True)
                self.inflight_resources[key] = ticket
            if raw_id:
                self._seen_calls.add(raw_id)
            self.admitted.add(ticket)
            self.tickets[ticket] = (tool, sig, call_id)
            if call_id and call_id != ticket:
                self._by_call[call_id] = ticket
            self._tls.ticket = ticket
            return None

    def cancellation_fence(self):
        with self.lock:
            return 'USER_CANCEL' if self.cancelled() else self.stop_reason

    # ---- outcomes -------------------------------------------------------
    def _record_outcome(self, tool, args, result_text):
        sig = call_signature(tool, args)
        failed, category = classify(tool, result_text)
        workdir = _norm_path(args.get('workdir')) if tool == 'terminal' else None
        if failed and category in ('permission_denied', 'not_found'):
            for path, cat in failed_locations(result_text, workdir).items():
                self.location_fences[path] = (cat, self.epoch)
            location = explicit_search_location(tool, args)
            if location:
                self.location_fences[location] = (category, self.epoch)
        out = outcome_digest(result_text)
        prev = self.outcomes.get(sig)
        repeats = prev[2] + 1 if prev and prev[0] == self.epoch and prev[1] == out else 1
        self.outcomes[sig] = (self.epoch, out, repeats)
        if failed and category in ('permission_denied', 'not_found', 'missing_dependency'):
            self.signature_fences[sig] = ('deterministic_failure', category, self.epoch)
        elif failed and repeats >= 2:
            self.signature_fences[sig] = ('repeated_failure', category, self.epoch)
        elif not failed and tool in SEARCH_TOOLS and empty_search_result(str(result_text)) and repeats >= 2:
            self.signature_fences[sig] = ('repeated_empty_search', None, self.epoch)
        elif not failed and tool not in POLLING_TOOLS and repeats >= REPEAT_SUCCESS_LIMIT:
            self.signature_fences[sig] = ('repeated_identical_result', None, self.epoch)
        if not failed:
            self.consecutive_blocked = 0
            if tool in MUTATING_TOOLS or (tool == 'terminal' and command_head(str(args.get('command', ''))) not in READ_ONLY_COMMANDS):
                self.epoch += 1  # state may have changed: earlier fences no longer prove futility
        else:
            # A real (non-blocked) attempt is progress of a kind; only blocked
            # choices count toward the consecutive-block loop detector.
            self.consecutive_blocked = 0
        self._note('failed' if failed else 'ok', tool, sig, category=category)
        return failed, category

    def finish(self, tool, args, call_id, result):
        text = result if isinstance(result, str) else json.dumps(result)
        with self.lock:
            failed, category = self._record_outcome(tool, args, text)
        capped = tool in SEARCH_TOOLS or (tool == 'terminal' and command_head(str(args.get('command', ''))) in SEARCH_COMMANDS)
        raw = text.encode()
        if not capped or len(raw) <= MAX_RESULT_BYTES:
            return result
        destination = self.evidence_dir / (digest(str(self._ticket(call_id)) + ':' + digest(text)) + '.txt')
        try:
            directory = open_directory(self.profile_home, self.evidence_parts, create=True)
        except OSError:
            self._stop('EVIDENCE_STORE_BLOCKED', 'nonrecoverable', tool, call_signature(tool, args))
            raise
        try:
            fd = os.open(destination.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
            with os.fdopen(fd, 'wb') as out:
                out.write(raw)
        except FileExistsError:
            pass  # identical evidence already stored
        except OSError:
            self._stop('EVIDENCE_STORE_BLOCKED', 'nonrecoverable', tool, call_signature(tool, args))
            raise
        finally:
            os.close(directory)
        summary = {'truncated': True, 'original_bytes': len(raw),
                   'sha256': hashlib.sha256(raw).hexdigest(),
                   'evidence_path': str(destination),
                   'instruction': 'Narrow the search or advance its page; do not repeat this broad result.',
                   'preview': raw[:4096].decode(errors='replace')}
        if category:
            summary['error'] = category
        rendered = json.dumps(summary)
        while len(rendered.encode()) > MAX_RESULT_BYTES:
            if not summary['preview']:
                return json.dumps({'truncated': True, 'sha256': summary['sha256'], 'error': 'Evidence path exceeds display bound'})
            summary['preview'] = summary['preview'][:len(summary['preview'])//2]
            rendered = json.dumps(summary)
        return rendered

    def abandon(self, tool, args, call_id):
        with self.lock:
            ticket = self._resolve_ticket(call_id)
            if tool in SEARCH_TOOLS:
                key = inflight_key(tool, args)
                owner = self.inflight_resources.get(key)
                if owner is not None and (ticket is None or owner == ticket):
                    del self.inflight_resources[key]

    def execute_admitted(self, tool, args, call_id, callback):
        with self.lock:
            ticket = self._resolve_ticket(call_id)
            reason = self.cancellation_fence()
            if not reason and (ticket not in self.admitted or ticket in self.dispatched):
                reason = 'UNRESERVED_OR_DUPLICATE_DISPATCH'
            if not reason and self.saved_artifact:
                try:
                    verify_saved_artifact(self.saved_artifact, self.profile_home)
                except (OSError, ValueError, TypeError):
                    reason = self._stop('SAVED_ARTIFACT_CHANGED_OR_UNVERIFIED', 'nonrecoverable', tool, call_signature(tool, args))
            if not reason:
                self.dispatched.add(ticket)
        if reason:
            self.abandon(tool, args, ticket)
            return BlockedResult(self.blocked_payload(reason))
        try:
            token = _active_guard.set(self)
            try:
                result = callback(args)
            except (PermissionError, FileNotFoundError) as exc:
                self.finish(tool, args, ticket, json.dumps({'error': type(exc).__name__+': '+str(exc)}))
                raise
            finally:
                _active_guard.reset(token)
            return self.finish(tool, args, ticket, result)
        finally:
            self.abandon(tool, args, ticket)
            if self.stop_reason:
                self.write_summary()

    def execute(self, tool, args, call_id, callback):
        ticket = self.new_ticket(call_id)
        reason = self.admit(tool, args, ticket)
        if reason:
            return BlockedResult(self.blocked_payload(reason))
        return self.execute_admitted(tool, args, ticket, callback)

    @staticmethod
    def is_blocked(result):
        return isinstance(result, BlockedResult)
