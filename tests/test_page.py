"""Browser tests of the key page, loaded from file:// in Playwright's Chromium.

Private key material exists only inside the temporary directory these tests
create and delete; no assertion message ever carries it.
"""
import base64
import re
import subprocess
import tempfile
import unittest
from pathlib import Path
from urllib.parse import urlsplit

from playwright.sync_api import sync_playwright

PAGE = Path(__file__).resolve().parent.parent / "index.html"
HUB_KEY = "qh+qUrZtbgsMm4A7qxGmSGHn+BiOi42uHCuxFFEpLFU="
WG = "/usr/bin/wg"
# 32 bytes in base64: 43 characters, the last carrying 4 bits and 2 zero bits, then one "=".
KEY = re.compile(r"[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=")


class KeyPageTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="vpn-key-test-")
        cls.playwright = sync_playwright().start()
        cls.browser = cls.playwright.chromium.launch(downloads_path=cls.tmp.name)

    @classmethod
    def tearDownClass(cls):
        cls.browser.close()
        cls.playwright.stop()
        cls.tmp.cleanup()

    def setUp(self):
        self.context = self.browser.new_context(accept_downloads=True)
        self.addCleanup(self.context.close)
        self.requests = []
        self.console = []
        self.errors = []
        self.context.on("request", lambda request: self.requests.append(request.url))
        self.page = self.context.new_page()
        self.page.on("console", lambda message: self.console.append(message.text))
        self.page.on("pageerror", lambda error: self.errors.append(error))

    def open(self):
        self.page.goto(PAGE.as_uri())
        self.page.locator("#steps").wait_for(state="visible")
        self.assertTrue(self.page.locator("#unsupported").is_hidden())

    def assert_quiet(self):
        """The page requested nothing but itself, and wrote nothing to the console."""
        others = [urlsplit(url).scheme for url in self.requests if url != PAGE.as_uri()]
        self.assertTrue(PAGE.as_uri() in self.requests, "the page itself was not recorded")
        self.assertTrue(not others, f"{len(others)} other requests, schemes {others}")
        self.assertTrue(not self.console, f"{len(self.console)} console messages")
        self.assertTrue(not self.errors, f"{len(self.errors)} page errors")

    def shown(self):
        """Everything the page shows or holds in its document."""
        return self.page.evaluate(
            """() => [
                document.documentElement.outerHTML,
                document.body.innerText,
                ...Array.from(document.querySelectorAll('input, output'), (field) => field.value),
            ].join('\\n')"""
        )

    def test_policy_forbids_every_request(self):
        html = PAGE.read_text(encoding="utf-8")
        match = re.search(r'<meta http-equiv="Content-Security-Policy" content="([^"]+)">', html)
        self.assertIsNotNone(match)
        policy = dict(part.strip().split(" ", 1) for part in match.group(1).split(";"))
        for directive in ("default-src", "connect-src", "form-action", "base-uri"):
            self.assertEqual(policy[directive], "'none'", directive)
        self.assertEqual(policy["script-src"], "'unsafe-inline'")
        self.assertEqual(policy["style-src"], "'unsafe-inline'")
        self.assertEqual(policy["img-src"], "data:")

        self.open()
        refused_by = self.page.evaluate(
            """() => new Promise((resolve) => {
                document.addEventListener('securitypolicyviolation',
                    (event) => resolve(event.effectiveDirective), { once: true });
                setTimeout(() => resolve('no violation'), 5000);
                fetch('https://example.invalid/').catch(() => {});
            })"""
        )
        self.assertEqual(refused_by, "connect-src")

    def test_bad_address_is_refused(self):
        self.open()
        for text in ("", "abc", "10.8.0.0", "10.8.0.1", "10.8.0.255", "10.8.0.256",
                     "10.8.1.23", "10.8.0.023", "10.8.0.23/32", "192.168.0.23", "10.8.0.23.4"):
            with self.subTest(address=text):
                self.page.fill("#address", text)
                self.page.click("#make")
                self.assertTrue(self.page.locator("#address-error").is_visible())
                self.assertTrue(self.page.locator("#made").is_hidden())
                self.assertTrue(self.page.locator("#save").is_disabled())
                self.assertTrue(self.page.locator("#address").is_enabled())
        self.assert_quiet()

    def test_first_and_last_address_are_accepted(self):
        for address in ("10.8.0.2", "10.8.0.254"):
            with self.subTest(address=address):
                self.open()
                self.page.fill("#address", address)
                self.page.press("#address", "Enter")
                self.page.locator("#made").wait_for(state="visible")
                self.assertEqual(self.page.locator("#made-for").inner_text(), address)
                self.assertTrue(self.page.locator("#address-error").is_hidden())
        self.assert_quiet()

    def test_key_file_holds_the_private_half_of_the_public_key_shown(self):
        self.context.grant_permissions(["clipboard-read", "clipboard-write"])
        self.open()
        self.page.fill("#address", " 10.8.0.23 ")
        self.page.click("#make")
        self.page.locator("#made").wait_for(state="visible")
        public = self.page.locator("#public-key").inner_text()
        self.assertRegex(public, KEY)
        self.assertEqual(self.page.locator("#made-for").inner_text(), "10.8.0.23")
        self.assertTrue(self.page.locator("#address").is_disabled())
        self.assertTrue(self.page.locator("#make").is_disabled())

        self.page.click("#copy")
        self.page.locator("#copied").wait_for(state="visible")
        self.assertEqual(self.page.locator("#copied").inner_text(), "Copied.")
        self.assertEqual(self.page.evaluate("navigator.clipboard.readText()"), public)

        shown_before_saving = self.shown()
        with self.page.expect_download() as info:
            self.page.click("#save")
        download = info.value
        self.addCleanup(download.delete)
        self.assertEqual(download.suggested_filename, "reelin.conf")
        saved = Path(download.path())
        self.assertTrue(saved.is_relative_to(self.tmp.name), "the download left the test's directory")
        lines = saved.read_text(encoding="utf-8").split("\n")

        expected = [
            "[Interface]",
            None,
            "Address = 10.8.0.23/32",
            "DNS = 10.8.0.1",
            "",
            "[Peer]",
            f"PublicKey = {HUB_KEY}",
            "AllowedIPs = 10.8.0.0/24, 10.80.0.0/16",
            "Endpoint = vpn.reelinrobotics.com:51820",
            "PersistentKeepalive = 25",
            "",
        ]
        self.assertTrue(len(lines) == len(expected), f"{len(lines) - 1} lines, expected {len(expected) - 1}")
        for number, (line, want) in enumerate(zip(lines, expected), start=1):
            if want is not None:
                self.assertTrue(line == want, f"line {number} is not {want!r}")
        self.assertTrue(lines[1].startswith("PrivateKey = "), "line 2 is not the PrivateKey line")
        private = lines[1].removeprefix("PrivateKey = ")
        self.assertTrue(KEY.fullmatch(private), "the private key is not 32 bytes in padded base64")
        secret = base64.b64decode(private, validate=True)
        self.assertTrue(secret[0] & 7 == 0 and secret[31] & 0xC0 == 0x40, "the private key is not clamped")
        self.assertTrue(private != public and private != HUB_KEY, "the private key equals a public key")

        derived = subprocess.run(
            [WG, "pubkey"], input=private + "\n", capture_output=True, text=True, check=True
        ).stdout.strip()
        self.assertEqual(derived, public)

        self.assertFalse(private in shown_before_saving, "the private key was on the page before saving")
        self.assertFalse(private in self.shown(), "the private key is on the page after saving")
        self.assertTrue(self.page.locator("#save").is_disabled())
        self.assertTrue(self.page.locator("#saved").is_visible())
        self.assertFalse(any(private in text for text in self.console), "the private key reached the console")

        stored = self.page.evaluate(
            "async () => [localStorage.length, sessionStorage.length, (await indexedDB.databases()).length]"
        )
        self.assertEqual(stored, [0, 0, 0], "local storage, session storage, IndexedDB databases")
        state = self.context.storage_state()
        self.assertTrue(not state["cookies"], f"{len(state['cookies'])} cookies")
        self.assertTrue(not state["origins"], f"{len(state['origins'])} origins with stored data")
        self.assert_quiet()

    def test_browser_without_x25519_is_sent_to_a_current_browser(self):
        self.page.add_init_script(
            "SubtleCrypto.prototype.generateKey = () =>"
            " Promise.reject(new DOMException('Algorithm: Unrecognized name', 'NotSupportedError'));"
        )
        self.page.goto(PAGE.as_uri())
        message = self.page.locator("#unsupported")
        message.wait_for(state="visible")
        self.assertIn("current Chrome, Edge, Firefox or Safari", message.inner_text())
        self.assertTrue(self.page.locator("#steps").is_hidden())
        self.assert_quiet()

    def test_browser_that_runs_no_script_is_sent_to_a_current_browser(self):
        context = self.browser.new_context(java_script_enabled=False)
        self.addCleanup(context.close)
        page = context.new_page()
        page.goto(PAGE.as_uri())
        message = page.locator("#unsupported")
        self.assertTrue(message.is_visible())
        self.assertIn("current Chrome, Edge, Firefox or Safari", message.inner_text())
        self.assertTrue(page.locator("#steps").is_hidden())


if __name__ == "__main__":
    unittest.main()
