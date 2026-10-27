/*
 * bgpdconf.js: reads and edits bgpd.conf(5) for the page. The text is
 * kept as lines. The reader finds statements and the neighbor, group and
 * rdomain blocks that hold them, and an edit adds, changes or removes the
 * lines of one statement and nothing else. Statements this code cannot
 * read are kept as written. The other routing daemons' configurations
 * share bgpd.conf's grammar, so routeconf.js reads them with this code,
 * giving its own block names. Nothing here uses the page, so the kit
 * runs it in node.
 */
"use strict";

/* blocks whose statements are parsed one by one */
var BGP_BLOCKS = ["neighbor", "group", "rdomain"];

/* the one-line neighbor settings this file reads */
var BGP_PEER = ["remote-as", "descr", "local-address", "multihop",
    "passive", "down", "max-prefix", "announce", "holdtime"];

/*
 * Split a line into code and comment, and count its braces outside quotes
 * and comments. A string is in double or single quotes, as the lexers
 * of these daemons read it. Report whether a backslash continues the line
 * or its comment. If cmt is set, the previous line ended in a continued
 * comment, so the whole line is comment.
 */
function bgpLine(line, cmt) {
	var code = "", depth = 0, q = false, i, c, rest, more;

	for (i = cmt ? line.length : 0; i < line.length; i++) {
		c = line[i];
		if (q) {
			if (c === "\\" && i + 1 < line.length) {
				code += c;
				c = line[++i];
			} else if (c === q)
				q = false;
		} else if (c === '"' || c === "'")
			q = c;
		else if (c === "#")
			break;
		else if (c === "{")
			depth++;
		else if (c === "}")
			depth--;
		code += c;
	}
	code = code.replace(/\r?\n$/, "");
	rest = (cmt ? line : line.slice(i)).replace(/\r?\n$/, "");
	more = rest !== "" && /\n$/.test(line) && /\\\r?$/.test(rest);
	return { code: code, depth: depth, comment: rest, more: more,
	    cont: more || /\\\s*$/.test(code) };
}

/* run bgpLine over lines in order, carrying comment continuation */
function bgpLines(lines) {
	var out = [], more = false;

	lines.forEach(function (line) {
		out.push(bgpLine(line, more));
		more = out[out.length - 1].more;
	});
	return out;
}

/* a word: a quoted string, a brace, or what runs up to a space or one */
var BGP_WORD = /"(?:[^"\\]|\\.)*"?|'(?:[^'\\]|\\.)*'?|[{}]|[^\s{}"']+/g;

/* split code into words: a quoted string is one word, and so is each brace */
function bgpWords(code) {
	return code.match(BGP_WORD) || [];
}

/*
 * Parse statements from line i up to the line that closes the enclosing
 * block, or the end. Each statement records its first line, the line
 * after its last, and its words; a block named in blocks also records
 * its statements and its closing line.
 */
function bgpNodes(lines, i, inner, blocks) {
	var out = [], n, l, depth, code, w, j;

	while (i < lines.length) {
		l = lines[i];
		if (inner && /^\s*}/.test(l.code))
			return { nodes: out, end: i };
		if (l.code.trim() === "") {
			i++;
			continue;
		}
		n = { start: i, comments: [] };
		code = "";
		depth = 0;
		for (j = i; j < lines.length; j++) {
			l = lines[j];
			code += (code ? " " : "") + l.code.replace(/\\\s*$/, "");
			if (l.comment)
				n.comments.push(l.comment);
			depth += l.depth;
			w = bgpWords(code);
			/* a block opens; its statements follow */
			if (j === i && blocks.indexOf(w[0]) !== -1 &&
			    w[w.length - 1] === "{" && depth === 1)
				break;
			if (!l.cont && depth <= 0)
				break;
		}
		n.code = code.trim();
		n.words = bgpWords(n.code);
		if (j === n.start && blocks.indexOf(n.words[0]) !== -1 &&
		    n.words[n.words.length - 1] === "{" && depth === 1) {
			l = bgpNodes(lines, j + 1, true, blocks);
			n.children = l.nodes;
			n.close = l.end;
			n.end = Math.min(l.end + 1, lines.length);
		} else if (j === n.start && blocks.indexOf(n.words[0]) !== -1 &&
		    n.words.slice(-2).join(" ") === "{ }") {
			/* an empty block on one line */
			n.children = [];
			n.close = n.start;
			n.end = n.start + 1;
		} else
			n.end = Math.min(j + 1, lines.length);
		n.kind = bgpKind(n);
		out.push(n);
		i = n.end;
	}
	return { nodes: out, end: i };
}

/* classify a statement by its first words */
function bgpKind(n) {
	var w = n.words;

	if (/^[A-Za-z][A-Za-z0-9_]*\s*=/.test(n.code))
		return "macro";
	if (n.children)
		return w[0];
	if (w[0] === "neighbor" || w[0] === "group" || w[0] === "rdomain")
		return "native";
	if (["allow", "deny", "match"].indexOf(w[0]) !== -1)
		return "filter";
	if (w[0] === "AS")
		return "as";
	if (w[0] === "router-id")
		return "routerid";
	if (w[0] === "network")
		return "network";
	return "other";
}

/* parse text into lines and statements; blocks defaults to bgpd's */
function bgpParse(text, blocks) {
	var lines = text.match(/[^\n]*\n|[^\n]+$/g) || [];
	var ls = bgpLines(lines);

	blocks = blocks || BGP_BLOCKS;
	return { lines: lines, read: ls, blocks: blocks,
	    nodes: bgpNodes(ls, 0, false, blocks).nodes };
}

function bgpText(doc) {
	return doc.lines.join("");
}

/* all of doc's nodes, each block followed by its statements */
function bgpAll(nodes, into) {
	into = into || [];
	nodes.forEach(function (n) {
		into.push(n);
		if (n.children)
			bgpAll(n.children, into);
	});
	return into;
}

/* a statement's text after its first word, or after its first k words */
function bgpRest(n, k) {
	var w = bgpWords(n.code), i, s = n.code;

	for (i = 0; i < (k || 1) && i < w.length; i++)
		s = s.slice(s.indexOf(w[i]) + w[i].length);
	return s.trim();
}

/* a string without its quotes; other words unchanged */
function bgpUnquote(s) {
	return /^(".*"|'.*')$/.test(s) ? s.slice(1, -1).replace(/\\(["'\\])/g,
	    "$1") : s;
}

/* a block's name: the words between its keyword and the brace */
function bgpName(n) {
	return n.words.slice(1, n.words.indexOf("{")).join(" ");
}

/*
 * List the neighbors at the top level and in groups and rdomains, each
 * with its group and the settings this file reads.
 */
function bgpPeers(doc) {
	var out = [];
	var walk = function (nodes, group) {
		nodes.forEach(function (n) {
			if (n.kind === "neighbor")
				out.push(bgpPeer(n, group));
			else if (n.children)
				walk(n.children, n.kind === "group" ? n : group);
		});
	};

	walk(doc.nodes, null);
	return out;
}

/* a neighbor's settings, falling back to its group's */
function bgpPeer(n, group) {
	var p = { node: n, address: bgpName(n), group: group ?
	    bgpUnquote(bgpName(group)) : "", groupNode: group, other: [] };
	var own = bgpSettings(n, p.other), g = group ?
	    bgpSettings(group, null) : {};

	BGP_PEER.forEach(function (k) {
		p[k] = own[k] !== undefined ? own[k] : "";
		p["group-" + k] = g[k] !== undefined ? g[k] : "";
	});
	return p;
}

/*
 * Read block n's known settings by name, each as the text after its
 * keyword, joining repeated ones with newlines. Push other statements
 * onto other.
 */
function bgpSettings(n, other) {
	var s = {};

	n.children.forEach(function (c) {
		var k = c.words[0];

		if (BGP_PEER.indexOf(k) === -1 || c.children) {
			if (other && c.kind !== "neighbor")
				other.push(c);
			return;
		}
		s[k] = s[k] !== undefined ? s[k] + "\n" + bgpRest(c) :
		    (c.words.length > 1 ? bgpRest(c) : "yes");
	});
	return s;
}

/* the indent of block n's statements, or n's indent plus a tab */
function bgpIndent(doc, n) {
	var c = n.children && n.children.length ? n.children[0] : null;

	return c ? /^\s*/.exec(doc.lines[c.start])[0] :
	    /^\s*/.exec(doc.lines[n.start])[0] + "\t";
}

/* replace doc's lines a to b with lines, and parse again */
function bgpSplice(doc, a, b, lines) {
	if (a > 0 && !/\n$/.test(doc.lines[a - 1]))
		doc.lines[a - 1] += "\n";
	Array.prototype.splice.apply(doc.lines, [a, b - a].concat(lines));
	return bgpParse(bgpText(doc), doc.blocks);
}

/* code as one line, with n's indent and n's comments after it */
function bgpLineOf(doc, n, code) {
	return /^\s*/.exec(doc.lines[n.start])[0] + code + (n.comments.length ?
	    " " + n.comments.join(" ") : "") + "\n";
}

/*
 * Set k in block n to value. Each line of value becomes one statement,
 * replacing the old ones or added before the block's closing brace; an
 * empty value removes them. A flag such as passive or down is present or
 * absent.
 */
function bgpSet(doc, n, k, value) {
	var old = n.children.filter(function (c) {
		return c.words[0] === k && !c.children;
	});
	var ind = bgpIndent(doc, n), lines = [], at, d;

	if (value === true)
		lines = [ind + k + "\n"];
	else if (value !== false && value !== "")
		lines = String(value).split("\n").filter(function (v) {
			return v.trim() !== "";
		}).map(function (v) {
			return ind + k + " " + (k === "descr" ? '"' +
			    bgpUnquote(v.trim()).replace(/"/g, '\\"') + '"' :
			    v.trim()) + "\n";
		});
	if (old.length) {
		at = old[0].start;
		/* remove the others from the last, so that at stays valid */
		for (d = old.length - 1; d > 0; d--)
			doc.lines.splice(old[d].start, old[d].end - old[d].start);
		if (lines.length === 1 && old[0].comments.length)
			lines[0] = lines[0].replace(/\n$/, " " +
			    old[0].comments.join(" ") + "\n");
		return bgpSplice(doc, at, old[0].end, lines);
	}
	if (lines.length === 0)
		return doc;
	if (n.close === n.start) {
		/* a one-line block, split over lines */
		at = /^\s*/.exec(doc.lines[n.start])[0];
		return bgpSplice(doc, n.start, n.start + 1, [at +
		    n.words.slice(0, -2).join(" ") + " {\n"].concat(lines,
		    [at + "}\n"]));
	}
	return bgpSplice(doc, n.close, n.close, lines);
}

/*
 * Add a top-level statement: after the last statement of one of the given
 * kinds, else before the first filter, else at the end.
 */
function bgpAdd(doc, code, after) {
	var top = doc.nodes, i, at = -1;

	for (i = 0; i < top.length; i++)
		if (after.indexOf(top[i].kind) !== -1)
			at = top[i].end;
	if (at === -1)
		for (i = top.length - 1; i >= 0; i--)
			if (top[i].kind === "filter")
				at = top[i].start;
	if (at === -1)
		at = doc.lines.length;
	return bgpSplice(doc, at, at, code.match(/[^\n]*\n|[^\n]+$/g) || []);
}

/* remove statement n and the comment lines just before it */
function bgpRemove(doc, n) {
	return bgpSplice(doc, bgpLead(doc, n), n.end, []);
}

/* the first comment line just before n, or n's first line */
function bgpLead(doc, n) {
	var a = n.start;

	while (a > 0 && doc.read[a - 1].code.trim() === "" &&
	    doc.read[a - 1].comment !== "")
		a--;
	return a;
}

/* move filter n and its comments up or down past the next filter */
function bgpMove(doc, n, d) {
	var fs = doc.nodes.filter(function (x) {
		return x.kind === "filter";
	});
	var i = fs.indexOf(n), o = fs[i + d], a, b, mine, theirs;

	if (i === -1 || o === undefined)
		return doc;
	if (d > 0) {
		a = n;
		b = o;
	} else {
		a = o;
		b = n;
	}
	mine = doc.lines.slice(bgpLead(doc, a), a.end);
	theirs = doc.lines.slice(bgpLead(doc, b), b.end);
	return bgpSplice(doc, bgpLead(doc, a), b.end, theirs.concat(
	    doc.lines.slice(a.end, bgpLead(doc, b)), mine));
}

/*
 * Parse a filter into action, quick, direction, peer, match and set, or
 * return null for a form this file does not read.
 */
function bgpFilter(n) {
	var w = n.words, f = { action: w[0] }, i = 1, j;

	if (w[i] === "quick") {
		f.quick = true;
		i++;
	}
	if (w[i] !== "from" && w[i] !== "to")
		return null;
	f.dir = w[i++];
	if (w[i] === "group" || w[i] === "AS") {
		f.peer = w[i] + " " + (w[i + 1] || "");
		i += 2;
	} else if (w[i] === "{") {
		j = w.indexOf("}", i);
		if (j === -1)
			return null;
		f.peer = w.slice(i, j + 1).join(" ");
		i = j + 1;
	} else if (i < w.length)
		f.peer = w[i++];
	else
		return null;
	j = w.indexOf("set", i);
	f.match = w.slice(i, j === -1 ? w.length : j).join(" ");
	f.set = j === -1 ? "" : w.slice(j + 1).join(" ");
	return f;
}

/* rebuild a filter's text from its parts */
function bgpFilterText(f) {
	return [f.action].concat(f.quick ? ["quick"] : [], [f.dir, f.peer],
	    f.match ? [f.match] : [], f.set ? ["set " + f.set] : []).join(" ");
}

/* doc's macros: each name's value, unquoted */
function bgpMacros(doc) {
	var m = {};

	doc.nodes.forEach(function (n) {
		var v;

		if (n.kind === "macro") {
			v = /^([A-Za-z][A-Za-z0-9_]*)\s*=\s*(.*)$/.exec(n.code);
			m[v[1]] = bgpUnquote(v[2].trim());
		}
	});
	return m;
}

/*
 * Decide whether filter f applies to peer p: yes, no, or maybe when the
 * filter names a list or an unknown macro.
 */
function bgpApplies(f, p, localAS, macros) {
	var as = p["remote-as"] || p["group-remote-as"];
	var val = function (s) {
		return /^\$/.test(s) && macros && macros[s.slice(1)] !==
		    undefined ? macros[s.slice(1)] : s;
	};

	if (f.peer === "any" || f.peer === p.address ||
	    val(f.peer) === val(p.address))
		return "yes";
	if (f.peer === "ebgp" || f.peer === "ibgp")
		return !as || !localAS ? "maybe" : (as === localAS) ===
		    (f.peer === "ibgp") ? "yes" : "no";
	if (/^group /.test(f.peer))
		return bgpUnquote(f.peer.slice(6)) === p.group ? "yes" : "no";
	if (/^AS /.test(f.peer))
		return !as ? "maybe" : f.peer.slice(3) === as ? "yes" : "no";
	if (/^[$({]/.test(val(f.peer)) || /^[$({]/.test(val(p.address)))
		return "maybe";
	return bgpUnquote(f.peer) === bgpUnquote(p.descr) ? "yes" : "no";
}

/*
 * Parse bgpctl's show summary: each peer's name, AS, message counts,
 * queue, up or down time and state. An established peer's state is its
 * prefix count.
 */
function bgpSummary(text) {
	var out = [];

	text.split("\n").forEach(function (l) {
		var m = /^(.*\S)\s+(\d+(?:\.\d+)?)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\S+)\s+(.+?)\s*$/.exec(l);

		if (m === null || /^Neighbor\s/.test(l))
			return;
		out.push({ name: m[1].trim(), as: m[2], rcvd: Number(m[3]),
		    sent: Number(m[4]), outq: Number(m[5]), updown: m[6],
		    state: /^\d+$/.test(m[7]) ? "Established" : m[7],
		    prefixes: /^\d+$/.test(m[7]) ? Number(m[7]) : null });
	});
	return out;
}
