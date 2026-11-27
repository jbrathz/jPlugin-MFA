/**
 * jPlugin-MFA — renders the otpauth:// URI into an inline SVG QR code and wires the
 * copy buttons. The secret never leaves the browser: no remote service.
 */
(function () {
	'use strict';

	function renderQr() {
		var nodes = document.querySelectorAll('[data-jmfa-qr]');

		if (!nodes.length || typeof qrcode === 'undefined') {
			return;
		}

		for (var i = 0; i < nodes.length; i++) {
			var node = nodes[i];
			var uri = node.getAttribute('data-jmfa-qr');

			if (!uri || node.getAttribute('data-jmfa-done') === '1') {
				continue;
			}

			try {
				var qr = qrcode(0, 'M');
				qr.addData(uri);
				qr.make();
				node.innerHTML = qr.createSvgTag({ cellSize: 6, margin: 2 });
				node.setAttribute('data-jmfa-done', '1');
			} catch (error) {
				node.textContent = uri;
			}
		}
	}

	function copyText(text) {
		if (navigator.clipboard && navigator.clipboard.writeText) {
			navigator.clipboard.writeText(text).catch(function () {});
			return;
		}

		var area = document.createElement('textarea');
		area.value = text;
		area.setAttribute('readonly', 'readonly');
		area.style.position = 'fixed';
		area.style.opacity = '0';
		document.body.appendChild(area);
		area.select();

		try {
			document.execCommand('copy');
		} catch (error) {
			// Clipboard unavailable; nothing else to do.
		}

		document.body.removeChild(area);
	}

	function bindCopy() {
		var buttons = document.querySelectorAll('[data-jmfa-copy]');

		for (var i = 0; i < buttons.length; i++) {
			buttons[i].addEventListener('click', function (event) {
				event.preventDefault();

				var button = this;
				var original = button.textContent;

				copyText(button.getAttribute('data-jmfa-copy') || '');
				button.textContent = '\u2713';

				window.setTimeout(function () {
					button.textContent = original;
				}, 1500);
			});
		}
	}

	function boot() {
		renderQr();
		bindCopy();
	}

	if (document.readyState === 'loading') {
		document.addEventListener('DOMContentLoaded', boot);
	} else {
		boot();
	}
})();