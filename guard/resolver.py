"""Where a Bash command's writes land (C1's resolver).

A text filter that looks for protected names in a command is easy to walk
around: split the name with quotes, `cd` first and use a relative path, build
the path in a variable, glob it, write through a symlink, or hide the write in
`python -c`. So the command is parsed instead (a quote-aware lexer: quoting
and concatenation vanish, heredoc bodies are split out, `$(...)` and
backticks are scanned on their own), `cd` and simple assignments are
followed from the payload's working folder, only real write targets are
collected, each is resolved to absolute paths (~, $HOME, globs, symlinks), and
the guard's roots decide. Reads pass whatever they name.

It fails closed in two places: inline interpreter code that names a protected
root, and a write target that can't be resolved in a command that names a
protected root (or runs inside one). A write from inside a script file
(`python3 /tmp/s.py`) is invisible to any check of command text: the effect
check (C2) is what sees it.
"""

from __future__ import annotations

import glob as _glob
import os
import re

from . import roots
from .config import Config

_OUT = {">", ">>", ">|", "&>", "&>>", "<>", ">&"}
_APPEND_OUT = {">>", "&>>"}
_KEYWORDS = {
    "if",
    "then",
    "else",
    "elif",
    "fi",
    "do",
    "done",
    "while",
    "until",
    "!",
    "time",
}
_PREFIX = {
    "sudo",
    "nohup",
    "time",
    "command",
    "exec",
    "builtin",
    "caffeinate",
    "stdbuf",
    "doas",
}
_FILE_ARGS = {
    "tee",
    "touch",
    "truncate",
    "rm",
    "trash",
    "unlink",
    "shred",
    "mkdir",
    "rmdir",
}
_DESTROY = {"rm", "trash", "unlink", "shred", "rmdir"}
_MODE_FIRST = {"chmod", "chown", "chgrp"}
_COPY = {"cp", "mv", "install", "ln", "ditto", "rsync"}
_SHELLS = {"bash", "sh", "zsh", "dash", "ksh", "fish"}
_INTERP = re.compile(
    r"^(?:python[\d.]*|perl|ruby|node|nodejs|php|osascript|rscript|deno|bun|lua)$", re.I
)
_GIT_WRITES = {
    "checkout",
    "restore",
    "reset",
    "clean",
    "rm",
    "mv",
    "apply",
    "stash",
    "merge",
    "rebase",
    "pull",
    "switch",
    "cherry-pick",
    "revert",
    "am",
}
_MUTATING = (
    _FILE_ARGS
    | _MODE_FIRST
    | _COPY
    | {"sed", "perl", "ruby", "dd", "patch", "tar", "zip", "unzip"}
)
_VAR = re.compile(r"\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))")
_HEREDOC = re.compile(r"(?<!<)<<(-?)\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\2")
_OPS = (
    "&>>",
    "<<<",
    "&&",
    "||",
    ";;",
    "|&",
    "&>",
    ">>",
    ">|",
    "<<",
    "<>",
    ">&",
    "<&",
    ";",
    "&",
    "|",
    "(",
    ")",
    "<",
    ">",
)
_SEP_OPS = {";", "&&", "||", "|", "|&", "&", ";;", "(", ")"}

# The old text check, kept as the fallback when the parser can't read a command.
WRITE_SHAPES = [
    re.compile(r">\|?>?\s*[^&\s|]"),
    re.compile(
        r"(?:^|[|;&\n(]|\bsudo\s+|\bxargs\s+)\s*"
        r"(?:/usr/bin/|/bin/|/usr/local/bin/|/opt/homebrew/bin/)?"
        r"(?:tee|cp|mv|ln|rm|trash|dd|truncate|shred|unlink|install|patch|"
        r"chmod|chown|chgrp|mkdir|rmdir|touch|rsync|zip|unzip|tar)\b"
    ),
    re.compile(r"\b(?:sed|perl|ruby)\s+(?:-\w*\s+)*-\w*i\b"),
    re.compile(r"\bgit\s+(?:apply|checkout|restore|clean|rm|mv|stash\s+pop)\b"),
]


class _Unresolved(Exception):
    pass


def looks_like_a_write(command: str) -> bool:
    return any(p.search(command) for p in WRITE_SHAPES)


def _unquoted_spans(text):
    """Yield (index, char, quoted?) so newlines and heredoc markers inside
    quotes are left alone."""
    q = None
    i = 0
    while i < len(text):
        c = text[i]
        if q is None:
            if c == "\\" and i + 1 < len(text):
                yield i, c, False
                yield i + 1, text[i + 1], True
                i += 2
                continue
            if c in "'\"":
                q = c
            yield i, c, False
        else:
            if q == '"' and c == "\\" and i + 1 < len(text):
                yield i, c, True
                yield i + 1, text[i + 1], True
                i += 2
                continue
            if c == q:
                q = None
                yield i, c, False
            else:
                yield i, c, True
        i += 1



def _tempdir() -> str:
    """$TMPDIR's fallback. tempfile costs ~4 ms to import, and every hook call
    would pay it, so it loads only when $TMPDIR isn't set."""
    import tempfile

    return tempfile.gettempdir()

def split_heredocs(command: str):
    """The command with every heredoc body cut out, and the bodies in order."""
    lines = command.split("\n")
    quoted_nl = set()  # line indexes that end inside quotes (multi-line strings)
    row = 0
    for _i, c, quoted in _unquoted_spans(command):
        if c == "\n":
            if quoted:
                quoted_nl.add(row)
            row += 1
    out, bodies, i = [], [], 0
    while i < len(lines):
        line = lines[i]
        out.append(line)
        i += 1
        if (i - 1) in quoted_nl:
            continue
        for m in _HEREDOC.finditer(line):
            dash, delim = m.group(1), m.group(3)
            body = []
            while i < len(lines):
                cand = lines[i].lstrip("\t") if dash else lines[i]
                i += 1
                if cand.strip() == delim:
                    break
                body.append(lines[i - 1])
            bodies.append("\n".join(body))
    return "\n".join(out), bodies


def _matching_paren(text, i):
    """Index of the ')' closing the '(' at text[i], skipping quoted text."""
    depth, q, j = 0, None, i
    while j < len(text):
        c = text[j]
        if q:
            if c == "\\" and q == '"':
                j += 2
                continue
            if c == q:
                q = None
        elif c in "'\"":
            q = c
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return j
        j += 1
    raise ValueError("unbalanced $(")


def lex(text):
    """(kind, value) tokens, kind 'word' or 'op'. Quotes are removed from words,
    but quoted text never becomes an operator (a quoted '>' stays a word).
    `$(...)` and backticks stay inside their word; their inner commands are
    returned too, for a scan of their own."""
    toks, inner, word, in_word = [], [], [], False
    i, n = 0, len(text)

    def flush():
        nonlocal word, in_word
        if in_word:
            toks.append(("word", "".join(word)))
        word, in_word = [], False

    while i < n:
        c = text[i]
        if c in " \t":
            flush()
            i += 1
        elif c == "\n":
            flush()
            toks.append(("op", ";"))
            i += 1
        elif c == "#" and not in_word:
            j = text.find("\n", i)
            i = n if j < 0 else j
        elif c == "\\":
            if i + 1 < n and text[i + 1] != "\n":
                word.append(text[i + 1])
                in_word = True
            i += 2
        elif c == "'":
            j = text.find("'", i + 1)
            if j < 0:
                raise ValueError("unbalanced '")
            word.append(text[i + 1 : j])
            in_word = True
            i = j + 1
        elif c == '"':
            j, buf = i + 1, []
            while j < n and text[j] != '"':
                if text[j] == "\\" and j + 1 < n:
                    if text[j + 1] != "\n":
                        buf.append(
                            text[j + 1] if text[j + 1] in '"\\$`' else text[j : j + 2]
                        )
                    j += 2
                elif text[j] == "$" and j + 1 < n and text[j + 1] == "(":
                    k = _matching_paren(text, j + 1)
                    inner.append(text[j + 2 : k])
                    buf.append(text[j : k + 1])
                    j = k + 1
                elif text[j] == "`":
                    k = text.find("`", j + 1)
                    if k < 0:
                        raise ValueError("unbalanced `")
                    inner.append(text[j + 1 : k])
                    buf.append(text[j : k + 1])
                    j = k + 1
                else:
                    buf.append(text[j])
                    j += 1
            if j >= n:
                raise ValueError('unbalanced "')
            word.append("".join(buf))
            in_word = True
            i = j + 1
        elif c == "$" and i + 1 < n and text[i + 1] == "(":
            k = _matching_paren(text, i + 1)
            inner.append(text[i + 2 : k])
            word.append(text[i : k + 1])
            in_word = True
            i = k + 1
        elif c == "`":
            k = text.find("`", i + 1)
            if k < 0:
                raise ValueError("unbalanced `")
            inner.append(text[i + 1 : k])
            word.append(text[i : k + 1])
            in_word = True
            i = k + 1
        elif c in ";&|()<>":
            if in_word and c in "<>" and "".join(word).isdigit():
                word, in_word = (
                    [],
                    False,
                )  # 2> , 1< : the fd number belongs to the redirect
            flush()
            op = next(o for o in _OPS if text.startswith(o, i))
            toks.append(("op", op))
            i += len(op)
        else:
            word.append(c)
            in_word = True
            i += 1
    flush()
    return toks, inner


def _opts_and_args(words):
    """Split words into (options, positional args); `--` ends options."""
    opts, args, after = [], [], False
    for w in words:
        if after or not w.startswith("-") or w == "-":
            args.append(w)
        elif w == "--":
            after = True
        else:
            opts.append(w)
    return opts, args


def _targets(cmd, rest):
    """(kind, token) write targets of one simple command. kind: 'append' (only
    adds), 'file' (rewrites) or 'tree' (removes, moves or fills a folder).
    None when the command writes somewhere it doesn't say."""
    t = []
    if cmd in ("sed", "perl", "ruby"):
        if not any(re.match(r"^-\w*i", w) or w.startswith("--in-place") for w in rest):
            return t  # not in place: output goes to stdout (or a redirect)
        words, script_given = [], False
        i = 0
        while i < len(rest):
            w = rest[i]
            if w in ("-e", "-f", "--expression", "--file"):
                script_given = True
                i += 2
                continue
            if (
                re.match(r"^-\w*i$", w)
                and i + 1 < len(rest)
                and rest[i + 1] == ""
                and cmd == "sed"
            ):
                i += 2  # macOS sed -i '' : an empty backup suffix
                continue
            if w.startswith("-"):
                if cmd in ("perl", "ruby") and w.endswith("e"):
                    script_given = True
                    i += 2
                    continue
                i += 1
                continue
            words.append(w)
            i += 1
        files = words if script_given else words[1:]
        return [("file", f) for f in files]
    if cmd == "tee":
        opts, args = _opts_and_args(rest)
        kind = (
            "append"
            if any(
                o in ("-a", "--append")
                or (o.startswith("-") and "a" in o[1:] and not o.startswith("--"))
                for o in opts
            )
            else "file"
        )
        return [(kind, a) for a in args]
    if cmd == "touch":
        opts, args = _opts_and_args(rest)
        return [("append", a) for a in args]
    if cmd in _FILE_ARGS:
        opts, args = _opts_and_args(rest)
        if cmd == "truncate":
            args = [a for a in args if not re.match(r"^[+-]?\d+[KMGkmg]?$", a)]
        return [("tree" if cmd in _DESTROY else "file", a) for a in args]
    if cmd in _MODE_FIRST:
        opts, args = _opts_and_args(rest)
        return [("tree", a) for a in args[1:]]
    if cmd in _COPY:
        opts, args = _opts_and_args(rest)
        dest = None
        for i, w in enumerate(rest):
            if w in ("-t", "--target-directory") and i + 1 < len(rest):
                dest = rest[i + 1]
            elif w.startswith("--target-directory="):
                dest = w.split("=", 1)[1]
        if dest is None:
            if len(args) < 2:
                return t
            dest, srcs = args[-1], args[:-1]
        else:
            srcs = [a for a in args if a != dest]
        if cmd == "rsync" and re.match(r"^[\w.-]+:", dest):
            return t  # a remote destination
        # Copying a file into a folder writes one entry there ("into"); copying a
        # folder's contents (`src/`, `.`) or pruning with --delete can rewrite
        # the whole tree below the destination.
        whole = any(src.endswith("/") or src in (".", "./") for src in srcs) or (
            cmd == "rsync" and any(w.startswith("--delete") for w in rest)
        )
        t.append(("tree" if whole else "into", dest))
        for s in srcs:
            base = os.path.basename(s.rstrip("/"))
            if base:
                t.append(("tree", dest.rstrip("/") + "/" + base))
            if cmd in ("mv", "ln"):
                t.append(("tree", s))  # moved away, or aliased
        return t
    if cmd == "dd":
        return [("file", w[3:]) for w in rest if w.startswith("of=")]
    if cmd == "tar":
        flags = "".join(w.lstrip("-") for w in rest[:1]) + "".join(
            w for w in rest if w.startswith("-")
        )
        into = next(
            (
                rest[i + 1]
                for i, w in enumerate(rest)
                if w in ("-C", "--directory") and i + 1 < len(rest)
            ),
            None,
        )
        if "t" in flags.replace("--", "") and "x" not in flags or "--list" in rest:
            return t  # a listing
        if "x" in flags or "--extract" in rest:
            return [("tree", into or ".")]
        archive = next(
            (
                rest[i + 1]
                for i, w in enumerate(rest)
                if w.endswith("f") and w.startswith("-") and i + 1 < len(rest)
            ),
            None,
        )
        return (
            [("file", archive)]
            if archive and ("c" in flags or "--create" in rest)
            else t
        )
    if cmd == "unzip" and any(re.match(r"^-[a-zA-Z]*[ltvpZz]", w) for w in rest):
        return t  # a listing, a test or a print to stdout: nothing is written
    if cmd == "unzip":
        into = next(
            (
                rest[i + 1]
                for i, w in enumerate(rest)
                if w == "-d" and i + 1 < len(rest)
            ),
            None,
        )
        return [("tree", into or ".")]
    if cmd == "zip":
        opts, args = _opts_and_args(rest)
        return [("file", args[0])] if args else t
    if cmd == "patch":
        return None  # its targets are inside the patch
    return t


def _git_targets(rest):
    """Write targets of a git command that rewrites working-tree files."""
    repo, i = None, 0
    while i < len(rest) and rest[i].startswith("-"):
        if rest[i] in ("-C", "-c", "--git-dir", "--work-tree") and i + 1 < len(rest):
            if rest[i] == "-C":
                repo = rest[i + 1]
            i += 2
        else:
            i += 1
    if i >= len(rest) or rest[i] not in _GIT_WRITES:
        return []
    sub, args = rest[i], rest[i + 1 :]
    if sub == "stash" and not (args and args[0] in ("pop", "apply")):
        return []
    if sub == "reset" and "--hard" not in args:
        return []
    paths = (
        args[args.index("--") + 1 :]
        if "--" in args
        else [a for a in args if not a.startswith("-")]
    )
    whole_tree = (
        "checkout",
        "switch",
        "merge",
        "rebase",
        "pull",
        "cherry-pick",
        "revert",
        "am",
        "clean",
        "stash",
        "reset",
    )
    if sub in whole_tree and "--" not in args:
        paths = []  # a branch or a ref, not a path: the whole tree changes
    base = repo if repo is not None else "."
    if not paths:
        return [("tree", base)]
    return [
        (
            "file",
            p if os.path.isabs(os.path.expanduser(p)) else base.rstrip("/") + "/" + p,
        )
        for p in paths
    ]


def _find_targets(rest):
    starts = []
    for w in rest:
        if w.startswith("-") or w in ("(", "!", "\\("):
            break
        starts.append(w)
    t = []
    for i, w in enumerate(rest):
        if w == "-delete":
            t += [("tree", s) for s in starts or ["."]]
        elif w in ("-exec", "-execdir", "-ok", "-okdir") and i + 1 < len(rest):
            inner = os.path.basename(rest[i + 1])
            if (
                inner in _MUTATING
                or inner in _SHELLS
                or _INTERP.match(inner)
                or inner == "xargs"
            ):
                t += [("tree", s) for s in starts or ["."]]
        elif w in ("-fprint", "-fprint0", "-fprintf", "-fls") and i + 1 < len(rest):
            t.append(("file", rest[i + 1]))
    return t


class Resolver:
    """Decides, for one config, whether a command writes into a guarded root."""

    def __init__(self, cfg: Config, tree_rule=None):
        self.cfg = cfg
        # Which whole-tree writes count (a recursive delete, a move, an
        # extraction, a git checkout): by default any tree that is, or holds,
        # a protected root.
        self.tree_rule = tree_rule or (lambda path: roots.holds_protected(path, cfg))
        self.collected: list[str] | None = None
        self.home = os.path.realpath(os.path.expanduser("~"))
        guarded = list(cfg.roots.protected) + list(cfg.roots.append_only)
        flags = re.IGNORECASE if cfg.case_insensitive else 0
        # How a command can name a protected root: its path in full, from ~ or
        # $HOME, or its last segment ("memory/", "MEMORY.md"). Inline code that
        # names one fails closed; so does an unresolvable write near one.
        root_names = []
        for root in cfg.roots.protected:
            root_names.extend(self._spellings(root))
            leaf = os.path.basename(root)
            if leaf and not re.search(r"[*?\[]", leaf):
                if os.path.splitext(leaf)[1]:
                    root_names.append(re.escape(leaf))
                else:
                    root_names.append(r"(?:^|[\s/'\"=])" + re.escape(leaf) + r"/")
        self.names_protected = (
            re.compile("|".join(root_names), flags) if root_names else None
        )
        # The command also names the area if it names a folder that holds a root.
        area = set()
        for root in guarded:
            area.update(self._spellings(os.path.dirname(root)))
        self.names_area = re.compile("|".join(sorted(area)), flags) if area else None
        self.dir_leaves = {
            (
                os.path.basename(r).lower()
                if cfg.case_insensitive
                else os.path.basename(r)
            )
            for r in cfg.roots.protected
            if not os.path.splitext(r)[1]
            and not re.search(r"[*?\[]", os.path.basename(r))
        }

    def _spellings(self, path: str) -> list[str]:
        """Regex spellings of an absolute path: as is, and from ~ / $HOME."""
        if not path or path == "/":
            return []
        out = [re.escape(path).replace(r"\*", "[^/]*")]
        if path.startswith(self.home + "/"):
            tail = re.escape(path[len(self.home) :]).replace(r"\*", "[^/]*")
            out += [r"~" + tail, r"\$HOME" + tail, r"\$\{HOME\}" + tail]
        return out

    # -- the decision ----------------------------------------------------------

    def _expand(self, tok, env):
        if tok.startswith("~"):
            tok = os.path.expanduser(tok)

        def sub(m):
            name = m.group(1) or m.group(2)
            if env.get(name) is None:
                raise _Unresolved(name)
            return env[name]

        try:
            tok = _VAR.sub(sub, tok)
        except _Unresolved:
            return None
        return None if ("$" in tok or "`" in tok) else tok

    def _resolve(self, tok, cwds, env):
        """Absolute paths a target can mean, or None when it can't be resolved."""
        e = self._expand(tok, env)
        if e is None or e == "":
            return None
        if os.path.isabs(e):
            bases = [""]
        elif None in cwds or not cwds:
            return None
        else:
            bases = cwds
        out = []
        for b in bases:
            p = os.path.normpath(os.path.join(b, e)) if b else os.path.normpath(e)
            if any(ch in p for ch in "*?["):
                out.extend(_glob.glob(p) or [p])
            else:
                out.append(p)
        return out

    def _guarded(self, path: str, kind: str) -> bool:
        if kind == "tree":
            return self.tree_rule(path)
        cls = roots.classify(path, self.cfg)
        return cls == "protected" or (cls == "append_only" and kind != "append")

    def _could_hold(self, folder: str, tree: bool) -> bool:
        """Could an unknown name inside this folder be guarded?"""
        if roots.classify(os.path.join(folder, "__guard_probe__"), self.cfg) in (
            "protected",
            "append_only",
        ):
            return True
        return tree and self.tree_rule(folder)

    def _near_guarded(self, folder: str | None) -> bool:
        return bool(folder) and (
            roots.holds_protected(folder, self.cfg)
            or self._could_hold(folder, tree=False)
        )

    def write_reason(
        self, command: str, cwd: str | None, _env=None, _cwds=None, _depth=0
    ) -> str | None:
        """Why this command writes into a guarded root, or None. Raises on
        anything it can't parse; the caller then falls back to the text check."""
        if _depth > 4:
            raise ValueError("nested too deep")
        env = (
            _env
            if _env is not None
            else {
                **{k: os.environ[k] for k in ("USER",) if k in os.environ},
                "TMPDIR": os.environ.get("TMPDIR") or _tempdir(),
                "HOME": self.home,
            }
        )
        cwds = (
            _cwds
            if _cwds is not None
            else ([os.path.normpath(os.path.expanduser(cwd))] if cwd else [None])
        )
        names = bool(
            (self.names_protected and self.names_protected.search(command))
            or (self.names_area and self.names_area.search(command))
        )
        text, bodies = split_heredocs(command)
        toks, inner = lex(text)
        for code in inner:  # $( ... ) and backticks run in a subshell of their own
            why = self.write_reason(code, None, dict(env), list(cwds), _depth + 1)
            if why:
                return why
        bodies = iter(bodies)
        events, cur, prev = [], [], None
        for kind, val in toks:
            if (kind == "op" and val in _SEP_OPS) or (
                kind == "word" and val in ("{", "}")
            ):
                events.append(("seg", cur, prev, val))
                cur = []
                if kind == "op" and val in ("(", ")"):
                    events.append((val,))
                prev = val
            else:
                cur.append((kind, val))
        events.append(("seg", cur, prev, None))
        saved = []

        def unresolved(what):
            if names or any(self._near_guarded(c) for c in cwds):
                return f"{what}, in a command that names a protected root"
            return None

        for event in events:
            if event[0] == "(":
                saved.append(list(cwds))
                continue
            if event[0] == ")":
                if saved:
                    cwds[:] = saved.pop()
                continue
            _, seg, prev_op, next_op = event
            piped = prev_op in ("|", "|&") or next_op in ("|", "|&")
            # Redirects apply whatever the command is, so they are collected first.
            targets, args, heredocs = [], [], []
            i = 0
            while i < len(seg):
                kind, val = seg[i]
                nxt = seg[i + 1] if i + 1 < len(seg) else None
                has_word = nxt is not None and nxt[0] == "word"
                if kind == "op" and val in _OUT:
                    if has_word and not (
                        val == ">&" and (nxt[1].isdigit() or nxt[1] == "-")
                    ):
                        targets.append(
                            ("append" if val in _APPEND_OUT else "file", nxt[1])
                        )
                    i += 2 if has_word else 1
                elif kind == "op" and val in ("<", "<<<", "<&"):
                    i += 2 if has_word else 1
                elif kind == "op" and val == "<<":
                    heredocs.append(next(bodies, ""))
                    i += 2 if has_word else 1
                else:
                    if kind == "word":
                        args.append(val)
                    i += 1
            while args and args[0] in _KEYWORDS:
                args.pop(0)
            cmd = ""
            if args and args[0] in ("for", "select", "case"):
                if args[0] in ("for", "select") and len(args) > 1:
                    env[args[1]] = None  # a loop variable: its values aren't known here
                args = []
            while args and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", args[0]):
                name, _, val = args.pop(0).partition("=")
                env[name] = self._expand(val, env)
            from_stdin = False
            while args:
                head = os.path.basename(args[0])
                if head in _PREFIX:
                    args.pop(0)
                    while args and args[0].startswith("-"):
                        args.pop(0)
                elif head == "env":
                    args.pop(0)
                    while args and (args[0].startswith("-") or "=" in args[0]):
                        a = args.pop(0)
                        if "=" in a and not a.startswith("-"):
                            n, _, v = a.partition("=")
                            env[n] = self._expand(v, env)
                elif head in ("nice", "timeout"):
                    args.pop(0)
                    while args and args[0].startswith("-"):
                        a = args.pop(0)
                        if a in ("-n", "-s", "-k") and args:
                            args.pop(0)
                    if head == "timeout" and args:
                        args.pop(0)  # the duration
                elif head == "xargs":
                    args.pop(0)
                    from_stdin = True
                    while args and args[0].startswith("-"):
                        a = args.pop(0)
                        if (
                            a in ("-n", "-I", "-P", "-L", "-d", "-s", "-E", "-J")
                            and args
                        ):
                            args.pop(0)
                else:
                    break
            if args:
                cmd = os.path.basename(args[0]).lower()
            rest = args[1:]
            if cmd in ("cd", "pushd"):
                dest = next((w for w in rest if not w.startswith("-")), None)
                e = (
                    self.home
                    if dest is None
                    else (None if dest == "-" else self._expand(dest, env))
                )
                if piped:
                    pass  # a cd inside a pipeline runs in a subshell: nothing persists
                elif e is None:
                    cwds.append(None)
                else:
                    new = []
                    for c in cwds:
                        if os.path.isabs(e):
                            nd = os.path.normpath(e)
                        elif c:
                            nd = os.path.normpath(os.path.join(c, e))
                        else:
                            nd = None
                        if nd not in new:
                            new.append(nd)
                    if all(d and os.path.isdir(d) for d in new):
                        cwds[:] = new  # the folder exists, so the cd succeeds
                    else:
                        cwds.extend(d for d in new if d not in cwds)
            elif cmd == "popd":
                cwds.append(None)
            elif cmd in ("export", "local", "declare", "typeset", "readonly"):
                for w in rest:
                    if "=" in w and not w.startswith("-"):
                        n, _, v = w.partition("=")
                        env[n] = self._expand(v, env)
            elif cmd == "read":
                for w in rest:
                    if not w.startswith("-"):
                        env[w] = None
            elif cmd in _SHELLS:
                codes = list(heredocs)
                if "-c" in rest and rest.index("-c") + 1 < len(rest):
                    codes.append(rest[rest.index("-c") + 1])
                for (
                    code
                ) in codes:  # a child shell: its cd and variables don't come back
                    why = self.write_reason(
                        code, None, dict(env), list(cwds), _depth + 1
                    )
                    if why:
                        return why
            elif cmd == "eval":
                why = self.write_reason(" ".join(rest), None, env, cwds, _depth + 1)
                if why:
                    return why
            elif _INTERP.match(cmd) and not (
                cmd in ("perl", "ruby") and any(re.match(r"^-\w*i", w) for w in rest)
            ):
                codes = list(heredocs)
                for j, w in enumerate(rest):
                    if w in ("-c", "-e", "-E", "--eval", "-r") and j + 1 < len(rest):
                        codes.append(rest[j + 1])
                if self.names_protected and any(
                    self.names_protected.search(c) for c in codes
                ):
                    return "inline code names a protected root (use grep, cat or sed to read it)"
                if from_stdin and not codes:
                    why = unresolved("code fed from stdin")
                    if why:
                        return why
            elif cmd == "git":
                targets += _git_targets(rest)
            elif cmd == "find":
                targets += _find_targets(rest)
            elif cmd in _MUTATING:
                got = _targets(cmd, rest)
                if got is None or from_stdin:
                    why = unresolved(f"`{cmd}` writes where the command does not say")
                    if why:
                        return why
                if got:
                    targets += got
            for kind, tok in targets:
                if tok.startswith("/dev/"):
                    continue
                e = self._expand(tok, env)
                if e is not None and not os.path.isabs(e):
                    first = e[2:] if e.startswith("./") else e
                    leaf = first.split("/", 1)[0]
                    if (
                        "/" in first
                        and (leaf.lower() if self.cfg.case_insensitive else leaf)
                        in self.dir_leaves
                    ):
                        if None in cwds or not cwds:
                            return f"a write to {e} (relative to an unknown folder)"
                paths = self._resolve(tok, cwds, env)
                if paths is None:
                    folder = os.path.dirname(tok)
                    if folder:
                        dirs = self._resolve(folder, cwds, env)
                    else:
                        dirs = None if (None in cwds or not cwds) else list(cwds)
                    if dirs is not None and not any(
                        self._could_hold(d, kind == "tree") for d in dirs
                    ):
                        continue  # the name is unknown, but the folder is outside every root
                    why = unresolved(f"a write to {tok!r} that cannot be resolved")
                    if why:
                        return why
                    continue
                for p in paths:
                    if self.collected is not None:
                        self.collected.append(p)
                    if self._guarded(p, kind):
                        return f"a write lands in {p}"
        return None

    def predicted_targets(self, command: str, cwd: str | None) -> list[str]:
        """Every write target the command names, resolved: the policy's intent,
        which the effect check compares with what really changed."""
        self.collected = []
        try:
            self.write_reason(command, cwd)
        finally:
            found, self.collected = self.collected, None
        return found

    def text_check(self, command: str) -> str | None:
        """The fallback when the parser can't read a command: a write-shaped
        command that names a protected root (and not only the append-only or
        allowed ones) is denied."""
        forms = (command, re.sub(r"""['"\\]""", "", command))
        if not looks_like_a_write(command):
            return None
        if self.names_protected and any(self.names_protected.search(f) for f in forms):
            return (
                "a write-shaped command naming a protected root (it couldn't be parsed)"
            )
        return None
