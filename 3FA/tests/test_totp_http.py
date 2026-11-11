import json
import socket
import subprocess
import sys
import threading
import time
import unittest
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from websockets.sync.client import connect

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from smart_server import SmartTOTPHandler


@contextmanager
def running_server(handler, **settings):
    with ThreadingHTTPServer(('127.0.0.1', 0), handler) as server:
        for name, value in settings.items():
            setattr(server, name, value)
        worker = threading.Thread(target=server.serve_forever)
        worker.start()
        try:
            yield server.server_port
        finally:
            server.shutdown()
            worker.join()


class TestCodeBackend(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != '/get_current_code':
            self.send_error(404)
            return
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'{"code":"483921","timeLeft":23}')

    def log_message(self, *args):
        pass


class TotpHttpTest(unittest.TestCase):
    def test_control_and_websocket_share_port_on_separate_addresses(self):
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            port = listener.getsockname()[1]
        script = Path(__file__).resolve().parents[1] / 'scripts' / 'websocket_server.py'
        with subprocess.Popen(
            [sys.executable, '-X', 'utf8', str(script), str(port), '127.0.0.2'],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        ) as process:
            try:
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline and process.poll() is None:
                    try:
                        update = Request(f'http://127.0.0.1:{port}/update_code', data=b'{"code":"483921"}')
                        with urlopen(update, timeout=1) as response:
                            self.assertEqual(response.status, 200)
                        with connect(f'ws://127.0.0.2:{port}', open_timeout=1, proxy=None) as client:
                            self.assertEqual(json.loads(client.recv(timeout=2))['code'], '483921')
                        return
                    except (OSError, URLError):
                        time.sleep(0.05)
                self.fail('The HTTP control API and WebSocket were not both reachable')
            finally:
                process.terminate()

    def test_phone_receives_current_code_over_http(self):
        with running_server(TestCodeBackend) as backend_port:
            with running_server(SmartTOTPHandler, websocket_port=backend_port) as phone_port:
                with urlopen(f'http://127.0.0.1:{phone_port}/get_current_code', timeout=3) as response:
                    self.assertEqual(json.load(response), {'code': '483921', 'timeLeft': 23})

    def test_published_port_requires_the_qr_token(self):
        with running_server(TestCodeBackend) as backend_port:
            with running_server(SmartTOTPHandler, websocket_port=backend_port, access_token='qr-token') as phone_port:
                url = f'http://127.0.0.1:{phone_port}/get_current_code'
                for query in ('', '?token=incorrect', '?token=%C3%A9'):
                    with self.subTest(query=query):
                        with self.assertRaises(HTTPError) as error:
                            urlopen(url + query, timeout=3).close()
                        self.assertEqual(error.exception.code, 404)
                with urlopen(url + '?token=qr-token', timeout=3) as response:
                    self.assertEqual(json.load(response)['code'], '483921')

    def test_close_status_is_shared_between_requests(self):
        with running_server(SmartTOTPHandler) as port:
            base_url = f'http://127.0.0.1:{port}'
            request = Request(base_url + '/close_page', data=b'{"action":"close"}')
            with urlopen(request, timeout=3) as response:
                self.assertEqual(json.load(response)['status'], 'success')
            with urlopen(base_url + '/check_close_status', timeout=3) as response:
                self.assertTrue(json.load(response)['shouldClose'])

    def test_phone_server_does_not_serve_project_files(self):
        with running_server(SmartTOTPHandler) as port:
            with self.assertRaises(HTTPError) as error:
                urlopen(f'http://127.0.0.1:{port}/', timeout=3).close()
            self.assertEqual(error.exception.code, 404)
