/*
 * pfconf.js: reads and edits pf.conf(5) for the page. The text is split
 * into statements, each kept exactly as written. The reader takes a
 * rule's common parts, a macro's value, a table's addresses and an
 * option's value from its words, and rewrites a statement only when one
 * of those changes. Statements this code cannot read, and all unchanged
 * ones, are kept as written. Nothing here uses the page, so the kit runs
 * it in node.
 */
"use strict";

/* words that begin a rule option, after the hosts */
var PF_OPTS = ["user", "group", "flags", "icmp-type", "icmp6-type", "tos",
    "keep", "modulate", "synproxy", "no", "fragment", "allow-opts", "once",
    "divert-packet", "divert-reply", "divert-to", "label", "tag", "tagged",
    "max-pkt-rate", "max-pkt-size", "set", "probability", "prio", "rtable",
    "af-to", "binat-to", "nat-to", "rdr-to", "route-to", "reply-to",
    "dup-to", "scrub", "received-on", "queue"];

/* words that begin a translation */
var PF_TRANSLATE = ["nat-to", "rdr-to", "binat-to", "af-to"];

/*
 * Split text into statements. A statement ends at a newline outside
 * quotes and braces, unless a backslash continues it; the last may have
 * no newline.
 */
function pfSplit(text) {
	var out = [], start = 0, depth = 0, q = false, cmt = false, i, c;

	for (i = 0; i < text.length; i++) {
		c = text[i];
		if (cmt) {
			/* a backslash at the end also continues a comment */
			if (c !== "\n" || /\\\r?$/.test(text.slice(start, i)))
				continue;
			cmt = false;
		} else if (q) {
			if (c === "\\")
				i++;
			else if (c === '"')
				q = false;
			continue;
		} else if (c === '"')
			q = true;
		else if (c === "#")
			cmt = true;
		else if (c === "{")
			depth++;
		else if (c === "}")
			depth--;
		if (c !== "\n" || depth > 0 || /\\\r?$/.test(text.slice(start,
		    i)))
			continue;
		out.push(text.slice(start, i + 1));
		start = i + 1;
	}
	if (start < text.length)
		out.push(text.slice(start));
	return out;
}

/*
 * Separate a statement's code from its comments: the code without
 * comments and with continued lines joined, and each comment as written.
 */
function pfCode(raw) {
	var code = "", cmts = [], q = false, i, c, e;

	for (i = 0; i < raw.length; i++) {
		c = raw[i];
		if (q) {
			code += c;
			if (c === "\\" && i + 1 < raw.length)
				code += raw[++i];
			else if (c === '"')
				q = false;
		} else if (c === '"') {
			q = true;
			code += c;
		} else if (c === "#") {
			e = raw.indexOf("\n", i);
			while (e !== -1 && /\\\r?$/.test(raw.slice(i, e)))
				e = raw.indexOf("\n", e + 1);
			e = e === -1 ? raw.length : e;
			cmts.push(raw.slice(i, e).replace(/\r$/, ""));
			i = e - 1;
		} else if (c === "\\" && /^\r?\n/.test(raw.slice(i + 1)))
			code += " ";
		else
			code += c;
	}
	return { code: code, comments: cmts };
}

/* collapse each run of white space outside quotes to one space */
function pfSquash(text) {
	return text.replace(/("(?:[^"\\]|\\.)*"?)|\s+/g, function (m, q) {
		return q !== undefined ? q : " ";
	}).trim();
}

/* split code into words, each with its start and end in code */
function pfTokens(code) {
	var out = [], i = 0, j;

	while (i < code.length) {
		if (/\s/.test(code[i])) {
			i++;
			continue;
		}
		if (code[i] === '"') {
			for (j = i + 1; j < code.length && code[j] !== '"'; j++)
				if (code[j] === "\\")
					j++;
			j = Math.min(j + 1, code.length);
		} else if ("{}(),".indexOf(code[i]) !== -1)
			j = i + 1;
		else
			for (j = i; j < code.length && !/[\s"{}(),]/.test(code[j]);)
				j++;
		out.push({ t: code.slice(i, j), s: i, e: j });
		i = j;
	}
	return out;
}

/*
 * the index after the unit at t[i], a word or a bracketed group; -1 if
 * there is none or it is not closed
 */
function pfUnit(t, i) {
	var open, close, depth = 0, j;

	if (i >= t.length)
		return -1;
	open = t[i].t;
	if (open !== "{" && open !== "(")
		return open === "}" || open === ")" ? -1 : i + 1;
	close = open === "{" ? "}" : ")";
	for (j = i; j < t.length; j++) {
		if (t[j].t === open)
			depth++;
		else if (t[j].t === close && --depth === 0)
			return j + 1;
	}
	return -1;
}

/* parse a rule's code into parts, or return null if this file cannot */
function pfRule(code) {
	var t = pfTokens(code), r = { opts: [] }, i = 0, j;
	var text = function (a, b) {
		return a < b ? pfSquash(code.slice(t[a].s, t[b - 1].e)) : "";
	};
	var optStart = function (k) {
		return k < t.length && (PF_OPTS.indexOf(t[k].t) !== -1 ||
		    (t[k].t === "!" && k + 1 < t.length &&
		    PF_OPTS.indexOf(t[k + 1].t) !== -1));
	};
	var stop = function (k) {
		return ["port", "os", "to", "from"].indexOf(t[k].t) !== -1 ||
		    optStart(k);
	};
	/* read a host and its port from i; return where they end, or -1 */
	var hosts = function (side) {
		var k = i;

		while (k < t.length && !stop(k))
			if ((k = pfUnit(t, k)) === -1)
				return -1;
		r[side] = text(i, k);
		if (k < t.length && t[k].t === "port") {
			i = k + 1;
			for (k = i; k < t.length && !stop(k);)
				if ((k = pfUnit(t, k)) === -1)
					return -1;
			if (k === i)
				return -1;
			r[side + "port"] = text(i, k);
		}
		if (side === "from" && k < t.length && t[k].t === "os") {
			i = k + 1;
			if ((k = pfUnit(t, i)) === -1)
				return -1;
			r.os = text(i, k);
		}
		return k;
	};

	if (t.length === 0 || ["pass", "block", "match"].indexOf(t[0].t) === -1)
		return null;
	r.action = t[i++].t;
	if (r.action === "block" && i < t.length &&
	    /^(drop|return|return-rst|return-icmp6?)$/.test(t[i].t)) {
		j = i + 1;
		if (j < t.length && t[j].t === "(" && (j = pfUnit(t, j)) === -1)
			return null;
		r.ret = text(i, j);
		i = j;
	}
	if (i < t.length && (t[i].t === "in" || t[i].t === "out"))
		r.dir = t[i++].t;
	if (i < t.length && t[i].t === "log") {
		j = i + 1;
		if (j < t.length && t[j].t === "(" && (j = pfUnit(t, j)) === -1)
			return null;
		r.log = text(i, j);
		i = j;
	}
	if (i < t.length && t[i].t === "quick") {
		r.quick = true;
		i++;
	}
	if (i < t.length && t[i].t === "on") {
		j = i + 1;
		if (j < t.length && t[j].t === "rdomain")
			j += 2;
		else if (j < t.length && t[j].t === "!")
			j = pfUnit(t, j + 1);
		else
			j = pfUnit(t, j);
		if (j === -1 || j > t.length)
			return null;
		r.on = text(i + 1, j);
		i = j;
	}
	if (i < t.length && (t[i].t === "inet" || t[i].t === "inet6"))
		r.af = t[i++].t;
	if (i < t.length && t[i].t === "proto") {
		if ((j = pfUnit(t, i + 1)) === -1)
			return null;
		r.proto = text(i + 1, j);
		i = j;
	}
	if (i < t.length && t[i].t === "all") {
		r.all = true;
		i++;
	} else {
		if (i < t.length && t[i].t === "from") {
			i++;
			if ((i = hosts("from")) === -1)
				return null;
		}
		if (i < t.length && t[i].t === "to") {
			i++;
			if ((i = hosts("to")) === -1)
				return null;
		}
	}
	while (i < t.length) {
		if (!optStart(i))
			return null;
		for (j = t[i].t === "!" ? i + 2 : i + 1; j < t.length &&
		    !optStart(j);)
			if ((j = pfUnit(t, j)) === -1)
				return null;
		r.opts.push({ word: t[i].t === "!" ? t[i + 1].t : t[i].t,
		    text: text(i, j) });
		i = j;
	}
	return r;
}

/* r's option, not negated, whose first word is in words, or null */
function pfOpt(r, words) {
	return r.opts.find(function (o) {
		return words.indexOf(o.word) !== -1 && !/^!/.test(o.text);
	}) || null;
}

/* copy r's state option, translations and label into fields */
function pfRuleFields(r) {
	var st = r.opts.find(function (o) {
		return ["keep", "modulate", "synproxy"].indexOf(o.word) !== -1 ||
		    /^no\s+state\b/.test(o.text);
	});
	var after = function (o) {
		return o ? o.text.replace(/^\S+\s*/, "") : "";
	};

	r.state = st ? st.text : "";
	r.natto = after(pfOpt(r, ["nat-to"]));
	r.rdrto = after(pfOpt(r, ["rdr-to"]));
	r.label = after(pfOpt(r, ["label"]));
	r.other = r.opts.filter(function (o) {
		return o !== st && !(["nat-to", "rdr-to", "label"].indexOf(
		    o.word) !== -1 && !/^!/.test(o.text));
	}).map(function (o) {
		return o.text;
	}).join(" ");
	return r;
}

/* rebuild a rule's text from its parts, keeping the options' order */
function pfRuleText(r) {
	var w = [r.action];

	if (r.action === "block" && r.ret)
		w.push(r.ret);
	if (r.dir)
		w.push(r.dir);
	if (r.log)
		w.push(r.log);
	if (r.quick)
		w.push("quick");
	if (r.on)
		w.push("on " + r.on);
	if (r.af)
		w.push(r.af);
	if (r.proto)
		w.push("proto " + r.proto);
	if (r.from || r.fromport || r.os) {
		w.push("from" + (r.from ? " " + r.from : ""));
		if (r.fromport)
			w.push("port " + r.fromport);
		if (r.os)
			w.push("os " + r.os);
	}
	if (r.to || r.toport) {
		w.push("to" + (r.to ? " " + r.to : ""));
		if (r.toport)
			w.push("port " + r.toport);
	}
	if (r.all && !r.from && !r.fromport && !r.os && !r.to && !r.toport)
		w.push("all");
	r.opts.forEach(function (o) {
		w.push(o.text);
	});
	return w.join(" ");
}

/*
 * Set field key of rule r to value. A part or option is changed in place,
 * added after the other options, or removed if value is empty.
 */
function pfRuleSet(r, key, value) {
	var words = { natto: "nat-to", rdrto: "rdr-to", label: "label" };
	var st, o, i;

	value = typeof value === "string" ? value.trim() : value;
	if (key === "state") {
		st = r.opts.findIndex(function (x) {
			return ["keep", "modulate", "synproxy"].indexOf(
			    x.word) !== -1 || /^no\s+state\b/.test(x.text);
		});
		o = { word: value.split(/\s+/)[0], text: value };
		if (st === -1 && value !== "")
			r.opts.push(o);
		else if (st !== -1 && value === "")
			r.opts.splice(st, 1);
		else if (st !== -1)
			r.opts[st] = o;
	} else if (words[key]) {
		i = r.opts.findIndex(function (x) {
			return x.word === words[key] && !/^!/.test(x.text);
		});
		o = { word: words[key], text: words[key] + " " + value };
		if (i === -1 && value !== "")
			r.opts.push(o);
		else if (i !== -1 && value === "")
			r.opts.splice(i, 1);
		else if (i !== -1)
			r.opts[i] = o;
	} else if (key === "other") {
		pfRuleFields(r);
		r.opts = r.opts.filter(function (x) {
			return r.state === x.text || (["nat-to", "rdr-to",
			    "label"].indexOf(x.word) !== -1 && !/^!/.test(x.text));
		});
		if (value !== "")
			r.opts.push({ word: value.split(/\s+/)[0], text: value });
	} else if (key === "log")
		r.log = value === true ? r.log || "log" : value || "";
	else
		r[key] = value;
	if (key === "from" || key === "to" || key === "fromport" ||
	    key === "toport")
		r.all = false;
	return pfRuleFields(r);
}

/* parse a statement: its kind, and its parts if this file reads it */
function pfStatement(raw) {
	var c = pfCode(raw), code = c.code.trim(), t = pfTokens(code);
	var s = { raw: raw, comments: c.comments, kind: "native",
	    indent: (/^[ \t]*/.exec(raw) || [""])[0],
	    eol: (/\r?\n$/.exec(raw) || [""])[0] };
	var m, j, k;

	if (code === "") {
		s.kind = c.comments.length ? "comment" : "blank";
		return s;
	}
	if ((m = /^([A-Za-z][A-Za-z0-9_]*)\s*=\s*([\s\S]*)$/.exec(code)) !==
	    null) {
		s.kind = "macro";
		s.name = m[1];
		s.value = pfSquash(m[2]);
		return s;
	}
	if (t[0].t === "set" && t.length > 1) {
		s.kind = "option";
		s.name = t[1].t;
		s.value = t.length > 2 ? pfSquash(code.slice(t[2].s)) : "";
		return s;
	}
	if (t[0].t === "table" && t.length > 1 && /^<.+>$/.test(t[1].t)) {
		s.name = t[1].t;
		s.flags = [];
		s.files = [];
		s.addrs = null;
		for (j = 2; j < t.length; j = k) {
			if (/^(persist|const|counters|optimize)$/.test(t[j].t)) {
				s.flags.push(t[j].t);
				k = j + 1;
			} else if (t[j].t === "file" && j + 1 < t.length) {
				s.files.push(t[j + 1].t);
				k = j + 2;
			} else if (t[j].t === "{" && s.addrs === null &&
			    (k = pfUnit(t, j)) !== -1)
				s.addrs = pfSquash(code.slice(t[j].e, t[k - 1].s));
			else
				return s;
		}
		s.kind = "table";
		return s;
	}
	if (/^(anchor|nat-anchor|rdr-anchor|binat-anchor)$/.test(t[0].t)) {
		s.kind = "anchor";
		s.name = t.length > 1 && t[1].t !== "{" ? t[1].t : "";
		j = code.indexOf("{");
		s.body = j !== -1 && code.lastIndexOf("}") > j ?
		    pfParse(code.slice(j + 1, code.lastIndexOf("}"))) : null;
		return s;
	}
	if ((s.rule = pfRule(code)) !== null) {
		s.kind = "rule";
		pfRuleFields(s.rule);
	}
	return s;
}

/* parse text into statements */
function pfParse(text) {
	return { stmts: pfSplit(text).map(pfStatement) };
}

/* join doc's statements back into text */
function pfText(doc) {
	return doc.stmts.map(function (s) {
		return s.raw;
	}).join("");
}

/*
 * Rewrite statement s from its parts, keeping its indent and comments:
 * one comment at the end of its line, and any others on lines before it.
 */
function pfWrite(s) {
	var code, lead = "", eol = s.eol || "\n";

	if (s.kind === "rule")
		code = pfRuleText(s.rule);
	else if (s.kind === "macro")
		code = s.name + " = " + s.value;
	else if (s.kind === "option")
		code = "set " + s.name + (s.value !== "" ? " " + s.value : "");
	else if (s.kind === "table")
		code = ["table", s.name].concat(s.flags, s.files.map(function (f) {
			return "file " + f;
		}), s.addrs !== null ? ["{ " + s.addrs + " }"] : []).join(" ");
	else
		return s.raw;
	if (s.comments.length > 1)
		lead = s.comments.slice(0, -1).map(function (c) {
			return s.indent + c + eol;
		}).join("");
	s.raw = lead + s.indent + code + (s.comments.length ?
	    " " + s.comments[s.comments.length - 1] : "") + eol;
	return s.raw;
}

/*
 * the index of the first statement that moves with statement i: it, or
 * the first of the comment lines directly before it
 */
function pfLead(doc, i) {
	var a = i;

	while (a > 0 && doc.stmts[a - 1].kind === "comment")
		a--;
	return a;
}

/* move statement i and its comments up or down past the next rule or anchor */
function pfMove(doc, i, d) {
	var kinds = ["rule", "anchor"], a = pfLead(doc, i), j, b, moving;

	for (j = i + d; j >= 0 && j < doc.stmts.length &&
	    kinds.indexOf(doc.stmts[j].kind) === -1; j += d)
		;
	if (j < 0 || j >= doc.stmts.length)
		return false;
	moving = doc.stmts.splice(a, i - a + 1);
	if (d < 0)
		b = pfLead(doc, j);
	else
		b = j - moving.length + 1;
	Array.prototype.splice.apply(doc.stmts, [b, 0].concat(moving));
	return true;
}

/* insert a statement of text after statement i, or at the end */
function pfInsert(doc, i, text) {
	var s = pfStatement(text + "\n");

	if (doc.stmts.length && !/\n$/.test(doc.stmts[doc.stmts.length -
	    1].raw))
		doc.stmts[doc.stmts.length - 1].raw += "\n";
	doc.stmts.splice(i < 0 ? doc.stmts.length : i + 1, 0, s);
	return s;
}

/* remove statement i and its comments */
function pfRemove(doc, i) {
	var a = pfLead(doc, i);

	doc.stmts.splice(a, i - a + 1);
}
