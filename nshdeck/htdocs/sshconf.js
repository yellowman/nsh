/*
 * sshconf.js: sshd_config, read and edited for the sshd editor. Each
 * line is a keyword and its value: the keyword in any case, then spaces
 * or one "=", then the value, where a word that begins with "#" outside
 * double quotes begins a comment. A Match line begins a section that
 * runs to the next Match line or the end of the file; section 0 is the
 * lines before the first. For most keywords sshd takes the first value
 * it reads, and for those marked many, each line adds a value. An edit
 * rewrites only the lines of the setting it changes, and keeps each
 * keyword as it was written. Nothing here uses the page, so the kit
 * runs it in node.
 */
"use strict";

var SSH_YESNO = ["yes", "no"];
var SSH_FORWARD = ["yes", "all", "no", "local", "remote"];

/*
 * The settings each tab shows, each keyword as sshd_config(5) spells it,
 * with its choices, or many if each line adds a value. A tab with lines
 * lists the lines of that keyword; one with other, the lines of the
 * keywords no tab shows; one with match, the Match sections.
 */
var SSH_TABS = [
	{ id: "listeners", label: "Listeners", keys: [
		{ kw: "Port", many: true },
		{ kw: "ListenAddress", many: true },
		{ kw: "AddressFamily", choices: ["any", "inet", "inet6"] },
		{ kw: "HostKey", many: true },
		{ kw: "HostCertificate", many: true }] },
	{ id: "auth", label: "Authentication", keys: [
		{ kw: "PermitRootLogin", choices: ["yes", "prohibit-password",
		    "forced-commands-only", "no"] },
		{ kw: "PasswordAuthentication", choices: SSH_YESNO },
		{ kw: "KbdInteractiveAuthentication", choices: SSH_YESNO },
		{ kw: "PubkeyAuthentication", choices: SSH_YESNO },
		{ kw: "PermitEmptyPasswords", choices: SSH_YESNO },
		{ kw: "AuthenticationMethods" },
		{ kw: "MaxAuthTries" },
		{ kw: "LoginGraceTime" },
		{ kw: "AuthorizedKeysFile" },
		{ kw: "TrustedUserCAKeys" }] },
	{ id: "access", label: "Access", keys: [
		{ kw: "AllowUsers", many: true },
		{ kw: "AllowGroups", many: true },
		{ kw: "DenyUsers", many: true },
		{ kw: "DenyGroups", many: true }], match: true },
	{ id: "forwarding", label: "Forwarding", keys: [
		{ kw: "AllowTcpForwarding", choices: SSH_FORWARD },
		{ kw: "AllowAgentForwarding", choices: SSH_YESNO },
		{ kw: "AllowStreamLocalForwarding", choices: SSH_FORWARD },
		{ kw: "X11Forwarding", choices: SSH_YESNO },
		{ kw: "PermitTunnel", choices: ["yes", "point-to-point",
		    "ethernet", "no"] },
		{ kw: "GatewayPorts", choices: ["no", "yes",
		    "clientspecified"] },
		{ kw: "DisableForwarding", choices: SSH_YESNO },
		{ kw: "PermitOpen" },
		{ kw: "PermitListen" }] },
	{ id: "limits", label: "Limits", keys: [
		{ kw: "MaxStartups" },
		{ kw: "MaxSessions" },
		{ kw: "ClientAliveInterval" },
		{ kw: "ClientAliveCountMax" }] },
	{ id: "algorithms", label: "Algorithms", keys: [
		{ kw: "Ciphers" },
		{ kw: "MACs" },
		{ kw: "KexAlgorithms" },
		{ kw: "HostKeyAlgorithms" },
		{ kw: "PubkeyAcceptedAlgorithms" }] },
	{ id: "subsystems", label: "Subsystems", lines: "Subsystem" },
	{ id: "other", label: "Other", other: true }
];

/* what a line's value risks, by keyword in lower case, given its section */
var SSH_WARN = {
	permitrootlogin: function (v, doc, sec) {
		return v === "yes" && (sshIn(doc, sec,
		    "PasswordAuthentication") !== "no" || sshIn(doc, sec,
		    "KbdInteractiveAuthentication") !== "no") ?
		    "root may log in with a password" : "";
	},
	permitemptypasswords: function (v, doc, sec) {
		return v === "yes" && sshIn(doc, sec,
		    "PasswordAuthentication") !== "no" ? "an account with no " +
		    "password may log in" : "";
	},
	gatewayports: function (v) {
		return v === "yes" ? "other hosts may reach forwarded ports" :
		    "";
	}
};

/* every registry entry the editor draws */
function sshFields() {
	var out = ["sshd.subsystem", "sshd.keyword", "sshd.value",
	    "sshd.match"];

	SSH_TABS.forEach(function (t) {
		(t.keys || []).forEach(function (k) {
			out.push("sshd." + k.kw.toLowerCase());
		});
	});
	return out;
}

/* whether a tab shows the lines of keyword kw, in lower case */
function sshShown(kw) {
	return kw === "match" || SSH_TABS.some(function (t) {
		return (t.lines || "").toLowerCase() === kw ||
		    (t.keys || []).some(function (k) {
			return k.kw.toLowerCase() === kw;
		});
	});
}

/* a line's value, up to its comment: a word that begins with "#" */
function sshComment(v) {
	var q = false, i;

	for (i = 0; i < v.length; i++) {
		if (v[i] === '"')
			q = !q;
		else if (!q && v[i] === "#" && (i === 0 ||
		    /\s/.test(v[i - 1])))
			return { value: v.slice(0, i).trim(),
			    comment: v.slice(i) };
	}
	return { value: v.trim(), comment: "" };
}

/*
 * text read: its lines; each line with a keyword, its line, indent,
 * keyword as written and in lower case, what follows the keyword, value,
 * comment and section; and the sections, each its Match line
 */
function sshParse(text) {
	var doc = { lines: text.match(/[^\n]*\n|[^\n]+$/g) || [], st: [],
	    secs: [{ at: -1, st: null }] };

	doc.lines.forEach(function (l, i) {
		var m = /^(\s*)([^\s=#"]+)(\s*=\s*|\s+|$)(.*?)\s*$/.exec(
		    l.replace(/\n$/, "")), c, s;

		if (!m)
			return;
		c = sshComment(m[4]);
		s = { i: i, ind: m[1], key: m[2], kw: m[2].toLowerCase(),
		    sep: m[3] || " ", value: c.value, comment: c.comment,
		    sec: doc.secs.length - 1 };
		if (s.kw === "match") {
			doc.secs.push({ at: i, st: s });
			s.sec = doc.secs.length - 1;
		}
		doc.st.push(s);
	});
	return doc;
}

/* the text of doc */
function sshText(doc) {
	return doc.lines.join("");
}

/* doc with its lines from at to end replaced by lines, each with a newline */
function sshSplice(doc, at, end, lines) {
	var all = doc.lines.slice(0, at).concat(lines, doc.lines.slice(end));

	return sshParse(all.map(function (l, i) {
		return i < all.length - 1 && !/\n$/.test(l) ? l + "\n" : l;
	}).join(""));
}

/* line s, with value v in place of its own */
function sshLine(doc, s, v) {
	return s.ind + s.key + s.sep + v + (s.comment ? " " + s.comment :
	    "") + (/\n$/.test(doc.lines[s.i]) ? "\n" : "");
}

/* the lines of keyword kw in section sec */
function sshFind(doc, sec, kw) {
	kw = kw.toLowerCase();
	return doc.st.filter(function (s) {
		return s.sec === sec && s.kw === kw;
	});
}

/* the values of keyword kw in section sec, and the first */
function sshValues(doc, sec, kw) {
	return sshFind(doc, sec, kw).map(function (s) {
		return s.value;
	});
}

function sshValue(doc, sec, kw) {
	return sshValues(doc, sec, kw)[0];
}

/* the value of keyword kw where section sec applies: its own, or section 0's */
function sshIn(doc, sec, kw) {
	var v = sshValue(doc, sec, kw);

	return v === undefined ? sshValue(doc, 0, kw) : v;
}

/* what line s risks, if anything */
function sshWarn(doc, s) {
	var w = SSH_WARN[s.kw];

	return w ? w(s.value, doc, s.sec) : "";
}

/*
 * where a new line of keyword kw goes in section sec, and its indent:
 * after the last of kw there, else after the section's last line, else
 * after its Match line; or in section 0, before the first Match line
 * and the comment lines just above it, or at the end if there is none
 */
function sshWhere(doc, sec, kw) {
	var mine = doc.st.filter(function (s) {
		return s.sec === sec && s.kw !== "match";
	}), same = sshFind(doc, sec, kw), at;
	var last = same.length ? same[same.length - 1] : mine[mine.length - 1];

	if (last)
		return { at: last.i + 1, ind: last.ind };
	if (sec > 0)
		return { at: doc.secs[sec].at + 1, ind: "\t" };
	if (doc.secs.length < 2)
		return { at: doc.lines.length, ind: "" };
	for (at = doc.secs[1].at; at > 0 && /^\s*#/.test(doc.lines[at - 1]);
	    at--)
		;
	return { at: at, ind: "" };
}

/*
 * keyword kw in section sec set to values, a line each: its lines
 * rewritten in order, those past the values removed, and the values
 * past its lines added after the last; none removes them all
 */
function sshSet(doc, sec, kw, values) {
	var list = sshFind(doc, sec, kw), lines = doc.lines.slice(), w;

	values = [].concat(values).map(function (v) {
		return String(v).trim();
	}).filter(function (v) {
		return v !== "";
	});
	list.forEach(function (s, i) {
		lines[s.i] = i < values.length ? sshLine(doc, s, values[i]) :
		    null;
	});
	if (values.length > list.length) {
		w = sshWhere(doc, sec, kw);
		lines = lines.slice(0, w.at).concat(values.slice(
		    list.length).map(function (v) {
			return w.ind + kw + " " + v + "\n";
		}), lines.slice(w.at));
	}
	return sshSplice(doc, 0, doc.lines.length, lines.filter(function (l) {
		return l !== null;
	}));
}

/* line s with value v, or removed if v is empty */
function sshSetLine(doc, s, v) {
	v = String(v).trim();
	return sshSplice(doc, s.i, s.i + 1, v === "" ? [] : [sshLine(doc, s,
	    v)]);
}

/* a line of keyword kw with value v added to section sec */
function sshAdd(doc, sec, kw, v) {
	var w = sshWhere(doc, sec, kw);

	return sshSplice(doc, w.at, w.at, [w.ind + kw + " " + v + "\n"]);
}

/* a Match section with criteria crit added at the end */
function sshAddMatch(doc, crit) {
	var last = doc.lines[doc.lines.length - 1];

	return sshSplice(doc, doc.lines.length, doc.lines.length,
	    (last !== undefined && last.trim() !== "" ? ["\n"] : []).concat(
	    ["Match " + crit + "\n"]));
}

/* Match section sec removed: its Match line through its last line */
function sshRemoveMatch(doc, sec) {
	var mine = doc.st.filter(function (s) {
		return s.sec === sec;
	});

	return sshSplice(doc, doc.secs[sec].at, mine[mine.length - 1].i + 1,
	    []);
}
