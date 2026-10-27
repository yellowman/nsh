/*
 * stmtconf.js: typed statements in the configurations of the daemons
 * whose files share bgpd.conf's grammar, read with bgpdconf.js. A
 * statement's kind names the words it begins with, the values that
 * follow them by position, and its options, each a keyword with a value
 * or alone. Reading gives each statement's fields. An edit rewrites only
 * the statement it changes, and in it only the words of the field it
 * changes, so words this file does not know stay as they were written.
 * Nothing here uses the page, so the kit runs it in node.
 *
 * A kind: id; kw, the words it begins with; args, its values by
 * position, each { key }; list, a value that may follow them any number
 * of times, { key }; opts, each { key, kw (the key if not given), n
 * (value words, 1 if not given), flag (no value) }; fixed, if its
 * grammar takes the options only in the order listed; block, if it
 * opens a block. A field marked raw is written as typed, word by word:
 * an address with a prefix length is one, as the grammars read the
 * slash as a word of its own.
 */
"use strict";

/* the words after kind k's own, and where they start */
function stBody(n, k) {
	var end = k.block ? n.words.indexOf("{") : n.words.length;

	return { at: k.kw.length, words: n.words.slice(k.kw.length,
	    end === -1 ? n.words.length : end) };
}

/* the option of kind k that the words from i begin, or null */
function stOptAt(k, w, i) {
	return (k.opts || []).find(function (o) {
		var kw = o.kw || [o.key];

		return kw.every(function (x, j) {
			return w[i + j] === x;
		});
	}) || null;
}

/* the kind of statement n, the one among kinds that matches most words */
function stKind(n, kinds) {
	var best = null;

	if (n.kind === "macro")
		return null;
	kinds.forEach(function (k) {
		if (!!k.block === !!n.children && k.kw.every(function (x, i) {
			return n.words[i] === x;
		}) && (!best || k.kw.length > best.kw.length))
			best = k;
	});
	return best;
}

/*
 * Statement n read as kind k: each field's value, unquoted, or true for
 * a flag, and an array for the list; where each is among n's words; and
 * the words no field takes
 */
function stRead(n, k) {
	var b = stBody(n, k), w = b.words, s = { node: n, kind: k, v: {},
	    at: {}, other: [] }, i = 0, o, kw, c;

	(k.args || []).forEach(function (a) {
		if (i < w.length && !stOptAt(k, w, i)) {
			s.v[a.key] = bgpUnquote(w[i]);
			s.at[a.key] = [b.at + i, 1];
			i++;
		}
	});
	while (i < w.length) {
		if ((o = stOptAt(k, w, i)) !== null) {
			kw = (o.kw || [o.key]).length;
			c = o.flag ? 0 : o.n || 1;
			s.v[o.key] = o.flag ? true : w.slice(i + kw, i + kw +
			    c).map(bgpUnquote).join(" ");
			s.at[o.key] = [b.at + i, kw + c];
			i += kw + c;
		} else if (k.list) {
			c = k.list.key;
			(s.v[c] = s.v[c] || []).push(bgpUnquote(w[i]));
			(s.at[c] = s.at[c] || []).push(b.at + i);
			i++;
		} else
			s.other.push(w[i++]);
	}
	return s;
}

/* the statements among nodes of the given kinds, each read */
function stList(nodes, kinds) {
	return nodes.map(function (n) {
		var k = stKind(n, kinds);

		return k ? stRead(n, k) : null;
	}).filter(Boolean);
}

/*
 * a value as one word: as it is if every one of these lexers reads it as
 * one word, else quoted
 */
function stQuote(v) {
	v = String(v);
	return /^[A-Za-z0-9_][A-Za-z0-9_.:-]*$/.test(v) ? v : '"' +
	    v.replace(/["\\]/g, "\\$&") + '"';
}

/* field key of kind k: its argument, option or list */
function stField(k, key) {
	return (k.args || []).concat(k.opts || [], k.list ? [k.list] :
	    []).find(function (f) {
		return f.key === key;
	}) || {};
}

/*
 * Set field key of statement s to value: an argument's word replaced; an
 * option's words replaced, or removed if value is "" or false, or added
 * after the options before it, if the kind's grammar fixes their order,
 * else last; the list's words replaced by value's lines
 */
function stSet(doc, s, key, value) {
	var k = s.kind, n = s.node, w = n.words.slice(), at = s.at[key];
	var o = (k.opts || []).find(function (x) {
		return x.key === key;
	}), f = stField(k, key), vals, end, pos, later;
	var q = function (x) {
		return f.raw ? x : stQuote(x);
	};

	vals = o && o.flag ? (value ? [] : null) : value === "" ||
	    value === false || value === undefined ? null :
	    String(value).trim().split(f.raw || o && (o.n || 1) > 1 ? /\s+/ :
	    /\n/).filter(function (x) {
		return x.trim() !== "";
	}).map(function (x) {
		return q(x.trim());
	});
	if (k.list && key === k.list.key) {
		vals = String(value).split(f.raw ? /\s+/ : "\n").map(
		    function (x) {
			return x.trim();
		}).filter(Boolean).map(q);
		at = (at || []).slice().sort(function (a, b) {
			return b - a;
		});
		pos = at.length ? at[at.length - 1] : stBody(n, k).at +
		    (k.args || []).length;
		at.forEach(function (i) {
			w.splice(i, 1);
		});
		Array.prototype.splice.apply(w, [pos, 0].concat(vals));
	} else if (!o) {
		/* an argument; it cannot be removed */
		if (vals === null || !at)
			return doc;
		Array.prototype.splice.apply(w, [at[0], 1].concat(vals));
	} else {
		if (at)
			w.splice(at[0], at[1]);
		if (vals !== null) {
			vals = (o.kw || [o.key]).concat(vals);
			end = k.block ? w.indexOf("{") : -1;
			/* in a fixed order, before the first option after it */
			later = k.fixed ? k.opts.slice(k.opts.indexOf(o) +
			    1).map(function (x) {
				return s.at[x.key];
			}).filter(Boolean).map(function (a) {
				return a[0];
			}) : [];
			pos = at ? at[0] : later.length ? Math.min.apply(null,
			    later) : end === -1 ? w.length : end;
			Array.prototype.splice.apply(w, [pos, 0].concat(vals));
		}
	}
	if (k.block)
		return bgpSplice(doc, n.start, n.start + 1, [bgpLineOf(doc,
		    n, w.join(" "))]);
	return bgpSplice(doc, n.start, n.end, [bgpLineOf(doc, n,
	    w.join(" "))]);
}

/* a new statement of kind k with its arguments, as a line of code */
function stNew(k, args) {
	return k.kw.concat((k.args || []).map(function (a, i) {
		return a.raw ? String(args[i]).trim() : stQuote(args[i]);
	}).filter(function (x, i) {
		return args[i] !== undefined && args[i] !== "";
	})).join(" ") + (k.block ? " {" : "");
}

/*
 * Add a statement of kind k with its arguments to block p, or the top
 * level if p is null: after the last statement of the same kind there,
 * else after the last of the kinds after, else at the end
 */
function stAdd(doc, p, k, args, after) {
	var nodes = p ? p.children : doc.nodes, ind, at;
	var code = stNew(k, args), last = function (kinds) {
		return nodes.filter(function (n) {
			return stKind(n, kinds) !== null;
		}).pop();
	};

	last = last([k]) || last(after || []);
	ind = p ? bgpIndent(doc, p) : "";
	if (last)
		at = last.end;
	else if (p)
		at = p.close === p.start ? -1 : p.close;
	else
		at = doc.lines.length;
	if (at === -1) {
		/* a one-line block, split over lines */
		ind = /^\s*/.exec(doc.lines[p.start])[0];
		return bgpSplice(doc, p.start, p.start + 1, [ind +
		    p.words.slice(0, -2).join(" ") + " {\n", ind + "\t" + code +
		    "\n", ind + "}\n"]);
	}
	if (last)
		ind = /^\s*/.exec(doc.lines[last.start])[0];
	return bgpSplice(doc, at, at, k.block ? [ind + code + "\n", ind +
	    "}\n"] : [ind + code + "\n"]);
}

/*
 * The one statement of kind k in block p, or the top level: set to
 * value, the text of its arguments, added if there is none, and removed
 * if value is empty
 */
function stSingle(doc, p, k, value) {
	var nodes = p ? p.children : doc.nodes, s = stList(nodes, [k])[0];

	value = String(value).trim();
	if (s && value === "")
		return bgpRemove(doc, s.node);
	if (s)
		return bgpSplice(doc, s.node.start, s.node.end, [bgpLineOf(doc,
		    s.node, k.kw.concat(stQuote(value)).join(" "))]);
	if (value === "")
		return doc;
	return stAdd(doc, p, k, [value]);
}
