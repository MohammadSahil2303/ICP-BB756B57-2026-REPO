import socket, threading, unittest
import portscan

def start_server(banner=b"SSH-2.0-TestServer\r\n"):
    srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(5)
    def loop():
        while True:
            try:
                c, _ = srv.accept(); c.sendall(banner); c.close()
            except OSError:
                return
    threading.Thread(target=loop, daemon=True).start()
    return srv

class T(unittest.TestCase):
    def test_parse(self):
        self.assertEqual(portscan.parse_ports("22,80,100-102"), [22, 80, 100, 101, 102])
        with self.assertRaises(ValueError): portscan.parse_ports("70000")
        with self.assertRaises(ValueError): portscan.parse_ports("50-10")
    def test_open_and_banner(self):
        srv = start_server(); port = srv.getsockname()[1]
        rep = portscan.run("127.0.0.1", [port], timeout=1)
        srv.close()
        self.assertEqual(len(rep["open"]), 1)
        self.assertEqual(rep["open"][0]["service"], "ssh")
    def test_closed(self):
        s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close()
        self.assertEqual(portscan.run("127.0.0.1", [p], timeout=0.5)["open"], [])
    def test_public_gate(self):
        with self.assertRaises(SystemExit):
            portscan.main(["8.8.8.8", "-p", "53"])
    def test_identify(self):
        self.assertEqual(portscan.identify(9999, "HTTP/1.1 200 OK"), "http")
        self.assertEqual(portscan.identify(3306, ""), "mysql")
if __name__ == "__main__":
    unittest.main()
