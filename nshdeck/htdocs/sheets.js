/*
 * sheets.js: xterm.js writes its styles into <style> elements, which the
 * page's content security policy (style-src 'self') refuses. Each one
 * xterm.js makes is instead an inert <template>, and the text it sets
 * there is a stylesheet the document adopts. The policy lets a script
 * make one, as it lets a script set an element's style. Loaded before
 * xterm.js
 */
"use strict";

(function () {
	var make = document.createElement.bind(document);

	document.createElement = function (tag, options) {
		var e, sheet, text = "";

		if (String(tag).toLowerCase() !== "style")
			return make(tag, options);
		e = make("template");
		sheet = new CSSStyleSheet();
		document.adoptedStyleSheets =
		    document.adoptedStyleSheets.concat([sheet]);
		Object.defineProperty(e, "textContent", {
			get: function () {
				return text;
			},
			set: function (t) {
				text = t;
				sheet.replaceSync(t);
			}
		});
		e.remove = function () {
			document.adoptedStyleSheets =
			    document.adoptedStyleSheets.filter(function (s) {
				return s !== sheet;
			});
			Element.prototype.remove.call(e);
		};
		return e;
	};
})();
