/*
 * nshdeck's page: nshd's answers, as nshdeck gives them, shown as text
 * and tables. Requests are forms, sent with X-Nshdeck: 1, which a page
 * of another site cannot send; answers are JSON. Every string nshd
 * sends is put in the page as text, never as HTML.
 */
"use strict";

var stream = null;		/* the event stream, while one is open */
var again = null;		/* the show to ask again on a kernel change */
var againTimer = null;
var LOGLINES = 2000;		/* log lines kept on the page, at most */

function $(id) {
	return document.getElementById(id);
}

/* an element of tag, with text, if any */
function el(tag, text) {
	var e = document.createElement(tag);

	if (text !== undefined)
		e.textContent = text;
	return e;
}

/* a request's answer, as JSON; a 401 shows the login again */
function ask(method, name, fields) {
	var body = new URLSearchParams(fields || {});
	var url = "api/" + name;
	var opts = { method: method, credentials: "same-origin",
	    headers: { "X-Nshdeck": "1" } };

	if (method === "GET") {
		if (body.toString() !== "")
			url += "?" + body.toString();
	} else
		opts.body = body;
	return fetch(url, opts).then(function (r) {
		if (r.status === 401 && name !== "login")
			loggedOut();
		return r.json().then(function (j) {
			j.httpStatus = r.status;
			return j;
		});
	});
}

/* what an answer says, as text: what nshd printed, or why it failed */
function said(j) {
	if (j.error !== undefined)
		return "% " + j.error + "\n";
	return j.output || "";
}

/* where the user is in configure, as nsh's prompt says it */
function where(ctx) {
	var modes = ["", "private", "shared", "exclusive", "terminal"];
	var s;

	if (!ctx || ctx.mode === 0)
		return "";
	s = "configure " + (modes[ctx.mode] || ctx.mode);
	if (ctx.interface)
		s += ", interface " + ctx.interface;
	if (ctx.rtable)
		s += ", rtable " + ctx.rtable;
	return s;
}

function context(j) {
	if (j.context === undefined)
		return;
	$("where").textContent = where(j.context);
	$("prompt").textContent = j.context.mode ?
	    "nsh(" + where(j.context) + ")>" : "nsh>";
}

/* records, a table for each kind, a column for each field any has */
function tables(records, into) {
	var kinds = {}, order = [];

	into.textContent = "";
	records.forEach(function (r) {
		if (r.kind === "message") {
			into.appendChild(el("pre", r.text));
			return;
		}
		if (!kinds[r.kind]) {
			kinds[r.kind] = [];
			order.push(r.kind);
		}
		kinds[r.kind].push(r);
	});
	order.forEach(function (k) {
		var cols = [], table = el("table"), tr = el("tr");

		kinds[k].forEach(function (r) {
			Object.keys(r).forEach(function (c) {
				if (c !== "kind" && cols.indexOf(c) === -1)
					cols.push(c);
			});
		});
		into.appendChild(el("h2", k + " (" + kinds[k].length + ")"));
		cols.forEach(function (c) {
			tr.appendChild(el("th", c));
		});
		table.appendChild(tr);
		kinds[k].forEach(function (r) {
			var row = el("tr");

			cols.forEach(function (c) {
				var v = r[c];

				row.appendChild(el("td", v === undefined ? "" :
				    Array.isArray(v) ? v.join(" ") : String(v)));
			});
			table.appendChild(row);
		});
		into.appendChild(table);
	});
}

function show(words) {
	var out = $("show-out");

	return ask("GET", "show", { words: words }).then(function (j) {
		tables(j.records || [], out);
		if (said(j) !== "")
			out.appendChild(el("pre", said(j)));
	});
}

/* to the transcript: what was asked, and what nshd said */
function transcript(asked, j) {
	var t = $("transcript");

	t.textContent += asked + "\n" + said(j);
	t.scrollTop = t.scrollHeight;
	context(j);
}

function configure(name, fields, asked) {
	return ask("POST", name, fields).then(function (j) {
		transcript(asked, j);
		return j;
	});
}

/* the event stream, following the logs checked */
function follow() {
	var logs = [];

	document.querySelectorAll("#events-form input:checked").forEach(
	    function (c) {
		logs.push(c.value);
	});
	if (stream)
		stream.close();
	stream = new EventSource("api/events" + (logs.length ?
	    "?logs=" + logs.join(",") : ""));
	stream.onopen = function () {
		$("stream-state").textContent = "live";
	};
	stream.onerror = function () {
		$("stream-state").textContent = "not live";
	};
	stream.addEventListener("notice", function (e) {
		noticed(JSON.parse(e.data));
	});
	stream.addEventListener("refused", function (e) {
		noticed({ kind: "refused", text: JSON.parse(e.data).text });
	});
	/* this page fell behind, and some events went: what it shows, again */
	stream.addEventListener("dropped", function () {
		$("log").textContent += "[some lines were dropped]\n";
		noticed({ kind: "dropped", text: "some events were dropped" });
		if (again)
			show(again);
	});
	stream.addEventListener("log", function (e) {
		var d = JSON.parse(e.data), log = $("log");
		var lines = (log.textContent + d.text).split("\n");

		if (lines.length > LOGLINES)
			lines = lines.slice(lines.length - LOGLINES);
		log.textContent = lines.join("\n");
		log.scrollTop = log.scrollHeight;
	});
}

function noticed(d) {
	var li = el("li"), list = $("notices");
	var text = new Date().toTimeString().slice(0, 8) + " " + d.kind;
	var whose = ["commit", "confirmed", "applied", "lock", "unlock"];

	if (whose.indexOf(d.kind) !== -1)
		text += " by uid " + d.uid;
	if (d.kind === "confirmed")
		text += ", " + d.n + " minutes";
	if (d.text)
		text += ": " + d.text.trim();
	li.textContent = text;
	list.insertBefore(li, list.firstChild);
	while (list.children.length > 200)
		list.removeChild(list.lastChild);
	/* a show of the kernel's, asked again once it settles */
	if ((d.kind === "links" || d.kind === "routes") && again &&
	    $("show-again").checked && !document.hidden) {
		clearTimeout(againTimer);
		againTimer = setTimeout(function () {
			show(again);
		}, 1000);
	}
}

function loggedIn(j) {
	$("who").textContent = j.user + " (" + j.perms.join(", ") + ")";
	$("login").hidden = true;
	$("deck").hidden = false;
	follow();
	again = $("show-form").words.value;
	show(again);
}

function loggedOut() {
	if (stream) {
		stream.close();
		stream = null;
	}
	$("deck").hidden = true;
	$("login").hidden = false;
}

function page(name) {
	document.querySelectorAll("nav button").forEach(function (b) {
		b.classList.toggle("on", b.dataset.page === name);
	});
	document.querySelectorAll("#deck > section").forEach(function (s) {
		s.hidden = s.id !== name;
	});
}

/* a form's submit, as fn of its fields, without leaving the page */
function on(id, fn) {
	$(id).addEventListener("submit", function (e) {
		e.preventDefault();
		fn(e.target);
	});
}

document.addEventListener("DOMContentLoaded", function () {
	on("login", function (f) {
		ask("POST", "login", { user: f.user.value,
		    password: f.password.value }).then(function (j) {
			f.password.value = "";
			if (j.httpStatus !== 200) {
				$("login-error").textContent = j.error;
				return;
			}
			$("login-error").textContent = "";
			loggedIn(j);
		});
	});
	$("logout").addEventListener("click", function () {
		ask("POST", "logout").then(loggedOut);
	});
	document.querySelectorAll("nav button").forEach(function (b) {
		b.addEventListener("click", function () {
			page(b.dataset.page);
		});
	});
	on("show-form", function (f) {
		again = f.words.value;
		show(again);
	});
	on("config-form", function (f) {
		var fields = { what: f.what.value };

		if (f.what.value === "rollback")
			fields.n = f.n.value;
		ask("GET", "config", fields).then(function (j) {
			$("config-out").textContent = said(j);
		});
	});
	on("configure-form", function (f) {
		configure("configure", { mode: f.mode.value },
		    "configure " + f.mode.value);
	});
	$("exit").addEventListener("click", function () {
		configure("exit", {}, "exit");
	});
	on("line-form", function (f) {
		var line = f.line.value;

		configure("line", { line: line }, $("prompt").textContent +
		    " " + line).then(function (j) {
			if (j.ok)
				f.line.value = "";
		});
	});
	on("commit-form", function (f) {
		var fields = {}, asked = "commit";

		if (f.minutes.value !== "") {
			fields.minutes = f.minutes.value;
			asked += " confirmed " + f.minutes.value;
		}
		if (f.comment.value !== "") {
			fields.comment = f.comment.value;
			asked += " comment " + f.comment.value;
		}
		configure("commit", fields, asked);
	});
	$("check").addEventListener("click", function () {
		configure("commit", { check: "1" }, "commit check");
	});
	$("diff").addEventListener("click", function () {
		ask("GET", "config", { what: "diff" }).then(function (j) {
			transcript("show diff-config", j);
		});
	});
	on("rollback-form", function (f) {
		configure("rollback", { n: f.n.value }, "rollback " + f.n.value);
	});
	on("op-form", function (f) {
		ask("POST", "op", { line: f.line.value,
		    rtable: f.rtable.value }).then(function (j) {
			var out = $("op-out");

			out.textContent = "";
			(j.records || []).forEach(function (r) {
				out.textContent += r.text !== undefined ?
				    r.text : JSON.stringify(r) + "\n";
			});
			out.textContent += said(j);
		});
	});
	on("events-form", follow);

	/* logged in already, if the cookie still says so */
	ask("GET", "whoami").then(function (j) {
		if (j.httpStatus === 200)
			loggedIn(j);
		else
			loggedOut();
	});
});
