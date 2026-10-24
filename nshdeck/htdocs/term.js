/*
 * term.js: a terminal, nsh on a pty, which nshdeck runs for the user
 * logged in (nshdeck(8)'s terminal and type). xterm.js draws it; what
 * nsh writes comes on the terminal's own event stream, in base64; and
 * what is typed goes in type requests, one at a time, in order, and
 * again a little later if nsh has not yet taken what came before
 */
"use strict";

var term = null;	/* xterm.js's terminal, once it is drawn */
var termfit = null;	/* its fit addon, which sizes it to its box */
var tstream = null;	/* the terminal's stream, while it is open */
var tnumber = 0;	/* its number, once nshdeck says it */
var typing = "";	/* typed, not yet sent */
var sending = false;	/* a type request not yet answered */

/* the terminal's state, in words, its light, and its buttons */
function tstate(text, led) {
	$("term-state").textContent = text;
	$("term-led").className = "led " + led;
	$("term-connect").disabled = tstream !== null;
	$("term-end").disabled = tstream === null;
}

/* what was typed, sent, 300 characters at most: 1023 bytes of UTF-8 */
function tsend() {
	var n = Math.min(typing.length, 300), keys;

	if (sending || tnumber === 0 || n === 0)
		return;
	/* not half of a character UTF-16 takes two for */
	if (n < typing.length && /[\uD800-\uDBFF]/.test(typing[n - 1]))
		n--;
	keys = typing.slice(0, n);
	typing = typing.slice(n);
	sending = true;
	ask("POST", "type", { terminal: tnumber, keys: keys }).then(
	    function (j) {
		sending = false;
		if (j.httpStatus === 503 && tnumber !== 0) {
			typing = keys + typing;
			setTimeout(tsend, 250);
		} else
			tsend();
	}, function () {
		sending = false;
	});
}

/* the terminal, drawn the first time, and an nsh started for it */
function tconnect() {
	if (tstream !== null)
		return;
	if (term === null) {
		term = new Terminal({ cursorBlink: true, fontSize: 13,
		    fontFamily: getComputedStyle(document.body)
		    .getPropertyValue("--mono").trim(), scrollback: 5000,
		    theme: { background: "#0b0d10", foreground: "#d7dce2",
		    cursor: "#4ea1ff", cursorAccent: "#0b0d10",
		    selectionBackground: "#2b4a6f" } });
		termfit = new FitAddon.FitAddon();
		term.loadAddon(termfit);
		term.open($("term"));
		term.onData(function (d) {
			/* a NUL cannot be sent */
			typing += d.replace(/\0/g, "");
			tsend();
		});
		term.onResize(function (s) {
			if (tnumber !== 0)
				ask("POST", "type", { terminal: tnumber,
				    keys: "", rows: s.rows, cols: s.cols });
		});
	}
	termfit.fit();
	tnumber = 0;
	typing = "";
	tstream = new EventSource("api/terminal?rows=" + term.rows +
	    "&cols=" + term.cols);
	tstate("starting nsh", "warn");
	tstream.addEventListener("terminal", function (e) {
		tnumber = JSON.parse(e.data).n;
		tstate("nsh, terminal " + tnumber, "on");
		term.focus();
	});
	tstream.addEventListener("out", function (e) {
		var s = atob(e.data), b = new Uint8Array(s.length), i;

		for (i = 0; i < s.length; i++)
			b[i] = s.charCodeAt(i);
		term.write(b);
	});
	tstream.addEventListener("end", function (e) {
		tgone(JSON.parse(e.data).text);
	});
	/* EventSource would ask again, which would start another nsh */
	tstream.onerror = function () {
		tgone("disconnected");
	};
}

/* the terminal's stream ended, and its nsh with it, as why says */
function tgone(why) {
	if (tstream === null)
		return;
	tstream.close();
	tstream = null;
	tnumber = 0;
	typing = "";
	why = why.trim();
	term.write("\r\n\x1b[2m[" + why + "]\x1b[0m\r\n");
	tstate(why, "off");
}

/* the Terminal workspace, shown: its terminal, connected if it is not */
function terminalShown() {
	if (tstream === null)
		tconnect();
	else {
		termfit.fit();
		term.focus();
	}
}

document.addEventListener("DOMContentLoaded", function () {
	$("term-connect").addEventListener("click", tconnect);
	$("term-end").addEventListener("click", function () {
		tgone("disconnected");
	});
	window.addEventListener("resize", function () {
		if (term !== null && !$("ws-terminal").hidden)
			termfit.fit();
	});
});
