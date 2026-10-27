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
 * (value words, 1 if not given), flag (no value), words (no keyword: the
 * option is one of these words) }; fixed, if its grammar takes the
 * options only in the order listed; block, true if it opens a block, or
 * "maybe" if it may. A field marked raw is written as typed, word by
 * word: an address with a prefix length is one, as the grammars read
 * the slash as a word of its own. A field marked group may be a list in
 * braces, and is read as an array.
 */
"use strict";

/* the words after kind k's own, up to n's block, and where they start */
function stBody(n, k) {
	var end = n.children ? n.words.indexOf("{") : -1;

	return { at: k.kw.length, words: n.words.slice(k.kw.length,
	    end === -1 ? n.words.length : end) };
}

/* the keyword words of option o: none if it is one of its words */
function stKw(o) {
	return o.words ? [] : o.kw || [o.key];
}

/* the option of kind k that the words from i begin, or null */
function stOptAt(k, w, i) {
	return (k.opts || []).find(function (o) {
		return o.words ? o.words.indexOf(w[i]) !== -1 :
		    stKw(o).every(function (x, j) {
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
		if ((k.block === "maybe" || !!k.block === !!n.children) &&
		    k.kw.every(function (x, i) {
			return n.words[i] === x;
		}) && (!best || k.kw.length > best.kw.length))
			best = k;
	});
	return best;
}

/*
 * the value of field f at word i of w: one word, or for a group a list
 * in braces, its commas dropped; and how many words it takes
 */
function stTake(f, w, i) {
	var j = i + 1, vals = [];

	if (!f.group || w[i] !== "{")
		return { vals: [bgpUnquote(w[i])], count: 1 };
	for (; j < w.length && w[j] !== "}"; j++)
		w[j].split(",").forEach(function (x) {
			if (x !== "")
				vals.push(bgpUnquote(x));
		});
	return { vals: vals, count: j + 1 - i };
}

/*
 * Statement n read as kind k: each field's value, unquoted, or true for
 * a flag, and an array for the list and a group; where each is among n's
 * words; and the words no field takes
 */
function stRead(n, k) {
	var b = stBody(n, k), w = b.words, s = { node: n, kind: k, v: {},
	    at: {}, other: [] }, i = 0, o, kw, t;

	(k.args || []).forEach(function (a) {
		if (i < w.length && !stOptAt(k, w, i)) {
			t = stTake(a, w, i);
			s.v[a.key] = a.group ? t.vals : t.vals[0];
			s.at[a.key] = [b.at + i, t.count];
			i += t.count;
		}
	});
	while (i < w.length) {
		if ((o = stOptAt(k, w, i)) !== null) {
			kw = stKw(o).length;
			t = o.flag ? { vals: [], count: 0 } : o.group ?
			    stTake(o, w, i + kw) : { vals: w.slice(i + kw, i +
			    kw + (o.n || 1)).map(bgpUnquote), count: o.n || 1 };
			s.v[o.key] = o.flag ? true : o.group ? t.vals :
			    t.vals.join(" ");
			s.at[o.key] = [b.at + i, kw + t.count];
			i += kw + t.count;
		} else if (k.list) {
			t = k.list.key;
			(s.v[t] = s.v[t] || []).push(bgpUnquote(w[i]));
			(s.at[t] = s.at[t] || []).push(b.at + i);
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
 * the words field f's value takes: none if it is empty; a group's lines
 * in braces if there are several; else each line, or each word if f is
 * written as typed or takes several words
 */
function stWords(f, value) {
	var vals = String(value).trim().split(f.raw || (f.n || 1) > 1 ?
	    /\s+/ : /\n/).map(function (x) {
		return x.trim();
	}).filter(Boolean).map(function (x) {
		return f.raw ? x : stQuote(x);
	});

	if (value === "" || value === false || value === undefined)
		return null;
	return f.group && vals.length > 1 ? ["{"].concat(vals, ["}"]) : vals;
}

/*
 * Set field key of statement s to value: an argument's words replaced; an
 * option's words replaced, or removed if value is "" or false, or added
 * after the options before it, if the kind's grammar fixes their order,
 * else last; the list's words replaced by value's lines
 */
function stSet(doc, s, key, value) {
	var k = s.kind, n = s.node, w = n.words.slice(), at = s.at[key];
	var f = stField(k, key), o = (k.opts || []).indexOf(f) !== -1 ? f :
	    null, vals = o && o.flag ? (value ? [] : null) : stWords(f, value);
	var end, pos, later;

	if (k.list && key === k.list.key) {
		vals = vals || [];
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
		Array.prototype.splice.apply(w, [at[0], at[1]].concat(vals));
	} else {
		if (at)
			w.splice(at[0], at[1]);
		if (vals !== null) {
			vals = stKw(o).concat(vals);
			end = n.children ? w.indexOf("{") : -1;
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
	return bgpSplice(doc, n.start, n.children ? n.start + 1 : n.end,
	    [bgpLineOf(doc, n, w.join(" "))]);
}

/* a new statement of kind k with its arguments, as a line of code */
function stNew(k, args) {
	return k.kw.concat((k.args || []).map(function (a, i) {
		return a.raw ? String(args[i]).trim() : stQuote(args[i]);
	}).filter(function (x, i) {
		return args[i] !== undefined && args[i] !== "";
	})).join(" ") + (k.block === true ? " {" : "");
}

/* statement n, which may open a block and does not, given an empty one */
function stOpen(doc, n) {
	var ind = /^\s*/.exec(doc.lines[n.start])[0];

	return bgpSplice(doc, n.start, n.end, [ind + n.code + " {" +
	    (n.comments.length ? " " + n.comments.join(" ") : "") + "\n",
	    ind + "}\n"]);
}

/*
 * Add a statement of kind k with its arguments to block p, or the top
 * level if p is null: after the last statement of the same kind there,
 * else after the last of the kinds after, else at the end. A statement p
 * that may open a block and does not is given one first.
 */
function stAdd(doc, p, k, args, after) {
	var nodes, ind, at, code = stNew(k, args), start;
	var last = function (kinds) {
		return nodes.filter(function (n) {
			return stKind(n, kinds) !== null;
		}).pop();
	};

	if (p && !p.children) {
		start = p.start;
		doc = stOpen(doc, p);
		p = bgpAll(doc.nodes).find(function (x) {
			return x.start === start;
		});
	}
	nodes = p ? p.children : doc.nodes;
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
	return bgpSplice(doc, at, at, k.block === true ? [ind + code + "\n",
	    ind + "}\n"] : [ind + code + "\n"]);
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
