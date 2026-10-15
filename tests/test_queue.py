"""Pruebas de la cola con reloj controlado y una base temporal por caso."""
import importlib.util
import os
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
spec = importlib.util.spec_from_file_location("cola_app", os.path.join(ROOT, "cola", "app.py"))
cola = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = cola
spec.loader.exec_module(cola)


class QueueTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.db_patch = patch.object(cola, "DB", os.path.join(self.directory.name, "cola.db"))
        self.db_patch.start()
        self.addCleanup(self.db_patch.stop)
        self.clock = patch.object(cola.time, "time", return_value=1000).start()
        self.addCleanup(patch.stopall)
        patch.object(cola, "QUEUE_INTERVAL", 3).start()
        cola.SESSIONS.clear()
        cola.init_db()
        self.client = cola.app.test_client()

    def status(self, client=None):
        return (client or self.client).get("/queue/status").get_json()

    def admit(self):
        self.client.get("/")
        self.clock.return_value += 3
        self.assertTrue(self.status()["admitted"])

    def test_login_requires_turn_in_both_modes(self):
        for mode in ("vuln", "fixed"):
            with self.subTest(mode=mode), patch.object(cola, "MODE", mode):
                for method in ("GET", "POST"):
                    response = self.client.open("/login", method=method,
                                                data={"usuario": "estudiante1", "clave": "clave123"})
                    self.assertEqual(response.status_code, 302)
                    self.assertEqual(response.location, "/")
                    self.assertNotIn("sid=", response.headers.get("Set-Cookie", ""))
        self.client.get("/")
        self.assertEqual(self.client.get("/login").location, "/")
        self.assertEqual(self.client.post("/login", data={"usuario": "estudiante1", "clave": "clave123"}).location, "/")

    def test_fifo_and_server_interval(self):
        second = cola.app.test_client()
        self.client.get("/")
        second.get("/")
        self.assertEqual(self.status()["position"], 1)
        self.assertEqual(self.status(second)["position"], 2)
        self.clock.return_value += 3
        # Aunque el segundo consulte primero, se admite al primero.
        self.assertFalse(self.status(second)["admitted"])
        self.assertTrue(self.status()["admitted"])
        self.assertEqual(self.status(second)["position"], 1)
        self.clock.return_value += 3
        self.assertTrue(self.status(second)["admitted"])

    def test_refresh_and_database_initialization_preserve_turn(self):
        original = self.client.get("/").headers["Set-Cookie"]
        cola.init_db()
        self.assertEqual(self.client.get("/").headers["Set-Cookie"], original)
        self.assertEqual(self.status()["position"], 1)

    def test_forged_or_missing_ticket_rejected(self):
        self.assertEqual(self.client.get("/queue/status").status_code, 401)
        with cola.app.test_request_context("/login", headers={"Cookie": "queue_ticket=falso"}):
            self.assertIsNone(cola.queue_state())
            self.assertFalse(cola.consume_queue_ticket())

    def test_abandoned_waiter_removed(self):
        self.client.get("/")
        self.clock.return_value += cola.QUEUE_IDLE_TIMEOUT + 1
        second = cola.app.test_client()
        second.get("/")
        self.assertEqual(self.status(second)["position"], 1)
        self.assertEqual(self.client.get("/queue/status").status_code, 401)

    def test_admission_expires_even_with_polling(self):
        self.admit()
        self.clock.return_value += cola.QUEUE_ADMISSION_TIMEOUT
        self.assertEqual(self.client.get("/queue/status").status_code, 401)
        self.assertEqual(self.client.get("/login").location, "/")
        self.assertEqual(self.client.post("/login", data={"usuario": "estudiante1", "clave": "clave123"}).location, "/")
        self.client.get("/")
        self.assertFalse(self.status()["admitted"])

    def test_invalid_credentials_keep_turn_success_consumes_it(self):
        self.admit()
        self.assertEqual(self.client.get("/login").status_code, 200)
        self.client.post("/login", data={"usuario": "estudiante1", "clave": "incorrecta"})
        self.assertTrue(self.status()["admitted"])
        response = self.client.post("/login", data={"usuario": "estudiante1", "clave": "clave123"})
        self.assertEqual(response.location, "/dashboard")
        self.assertEqual(self.client.get("/dashboard").status_code, 200)
        self.assertEqual(self.client.get("/queue/status").status_code, 401)

    def test_ticket_can_only_be_consumed_once_under_concurrency(self):
        response = self.client.get("/")
        cookie = response.headers["Set-Cookie"].split(";", 1)[0]
        self.clock.return_value += 3
        self.status()

        def consume(_):
            with cola.app.test_request_context("/login", headers={"Cookie": cookie}):
                return cola.consume_queue_ticket()

        with ThreadPoolExecutor(max_workers=4) as pool:
            self.assertEqual(sum(pool.map(consume, range(4))), 1)

    def test_ticket_is_private_and_status_is_not_cached(self):
        response = self.client.get("/")
        cookie = response.headers["Set-Cookie"]
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Strict", cookie)
        self.assertEqual(response.headers["Cache-Control"], "no-store")
        response = self.client.get("/queue/status")
        self.assertNotIn("token", response.get_json())
        self.assertEqual(response.headers["Cache-Control"], "no-store")
        self.admit()
        self.assertEqual(self.client.get("/login").headers["Cache-Control"], "no-store")


if __name__ == "__main__":
    unittest.main()
