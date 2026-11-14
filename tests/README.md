# nsh unit tests

Each test program links one or two nsh source files and supplies the rest itself. The tests need no root access, no network and no running daemons.

```sh
cd tests
make            # build and run all tests
make test       # the same
make clean
```

| Test | Links | Covers |
|---|---|---|
| `t_conftree` | `conftree.c` | Config tree:<br>• read and write round-trip<br>• set/sequence diff<br>• every `conftree_edit` op<br>• rejection of lines with newlines<br>• copy and journal replay |
| `t_facts` | `facts.c` | The facts protocol between nshd and the client:<br>• round trip of every value type, including extremes<br>• absent fields<br>• templates sent once per kind<br>• writer limits<br>• the `FACTS_FIELDS` limit, at and one past it, for writer and reader<br>• several units in one message, and a partial or repeated unit within one<br>• rejection of every truncation, wrong types, NULs in strings, bad address families and lengths, and bad templates<br>• binding fields by name<br>• 200,000 random corruptions of valid units, which must never crash or yield a value the template does not allow |
| `t_genget` | `genget.c` | Command-name prefix matching, exact matches and ambiguity |
| `t_makeargv` | `makeargv.c` | Command-line tokenising:<br>• quoting and escapes<br>• `!` shell escape<br>• the `margv[]` limit |
| `t_stringlist` | `stringlist.c` | String-list growth and joining |
| `t_hashtable` | `hashtable.c` | The session environment table:<br>• growth<br>• uniqueness<br>• remove<br>• foreach, including no adding during a walk |
| `t_session` | `session.c` | Per-session globals:<br>• every `SGLOBAL` table walked, each global its full size<br>• `session_enter()` puts a session's values in place<br>• `session_leave()` keeps them and restores the process's<br>• no session sees another's<br>• `margv` pointing into `line` survives a switch<br>• `session_free()` releases a session's candidate and rules file as that session<br>• 64 sessions at once |
| `t_ctlargs` | `ctlargs.c`, `genget.c` | `show <protocol> <what> [args]`:<br>• `step_optreq()` filling OPT and REQ slots, refusing extra words and a missing REQ<br>• `prot1_find()`: exact names, trailing spaces, never systat<br>• `pr_prot1()`: help, refusals, abbreviations, nshd's system or nsh running the program, bgpctl's socket |
| `t_globals.sh` | `globals.list`, `*.c` | Every global `globals.list` calls a session's is in an `SGLOBAL` table of its own file, and every `SGLOBAL` entry is listed as one |

The protocol tables in `t_ctlargs` are copies: the bgp table is `bgpcommands.c`'s and the ospf table is `commands.c`'s. If you change those tables, update the copies.

## Result lines

- `FAIL`: an expectation that should hold doesn't. The test exits non-zero.
- `XFAIL`: a known bug that isn't fixed yet. It doesn't fail the run. The message names the code location.
- `XPASS`: a known-bug check now passes, so the bug was fixed. This fails the run as a reminder to turn `KNOWN_BUG()` into `CHECK()`.

These known bugs are recorded at the moment:

- `t_genget`: an empty argument (`""`) matches the first table entry (`genget.c`, `isprefix()`).
- `t_makeargv`: a 1023-character line of single-character words gives 512 words. `makeargv()` then writes its terminating NULL at `margv[512]`, past the end of the array. This test runs in a forked child.
- `t_ctlargs`: four checks of one bug. `BGPSOCK` is two words (`-s` and the socket path), but `step_optreq()` only looks at the first `NOPTFILL - 1` = 6 slots of an entry. As a result:
  - `show bgp neighbor <peer> timers` is refused as "Superfluous argument";
  - `show bgp rib` takes 1 of its 3 arguments;
  - `show bgp ip` takes none of its arguments;
  - `NOPTFILL` is smaller than the 10 that the longest entry needs.

## Portability

`conftree.c` and `facts.c` are portable C. `t_conftree` and `t_facts` also build on Linux and macOS, and with MinGW if `reallocarray`, `strndup` and `getline` are supplied. `compat.c` provides them and `compat.h` declares them:

```sh
cc -include compat.h -o t_facts t_facts.c ../facts.c compat.c
```

On those systems they can also run under AddressSanitizer:

```sh
cc -g -fsanitize=address,undefined -o t_conftree t_conftree.c ../conftree.c
cc -g -fsanitize=address,undefined -o t_facts t_facts.c ../facts.c
```

`t_globals.sh` needs only a POSIX shell, `awk`, `sort` and `comm`.

The other tests include nsh's own headers. Those need OpenBSD's network headers, and the tests use OpenBSD interfaces (`strlcpy`, `siphash`, `arc4random`, `fork`), so they're meant to run on OpenBSD.

## Adding a test

When you fix a bug, first add a check that fails against the old code. When the fix can't be made yet, add a `KNOWN_BUG()` check instead.
