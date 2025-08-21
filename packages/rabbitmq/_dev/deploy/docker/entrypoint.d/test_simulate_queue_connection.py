import unittest
from unittest.mock import patch, MagicMock, call
import sys
import types

# Import the module under test as a module object
MODULE_PATH = './simulate_queue_connection.py'

class TestSimulateQueueConnection(unittest.TestCase):
    def setUp(self):
        # Patch pika, socket, time, os, and print for all tests
        patcher_pika = patch('pika.BlockingConnection')
        patcher_socket = patch('socket.create_connection')
        patcher_time = patch('time.sleep')
        patcher_os = patch('os.getenv', side_effect=lambda k, d=None: d)
        patcher_print = patch('builtins.print')
        self.mock_pika = patcher_pika.start()
        self.mock_socket = patcher_socket.start()
        self.mock_time = patcher_time.start()
        self.mock_os = patcher_os.start()
        self.mock_print = patcher_print.start()
        self.addCleanup(patcher_pika.stop)
        self.addCleanup(patcher_socket.stop)
        self.addCleanup(patcher_time.stop)
        self.addCleanup(patcher_os.stop)
        self.addCleanup(patcher_print.stop)
        # Import the module under test
        if 'simulate_queue_connection' in sys.modules:
            del sys.modules['simulate_queue_connection']
        self.module = types.ModuleType('simulate_queue_connection')
        with open(MODULE_PATH) as f:
            code = f.read()
        exec(code, self.module.__dict__)

    def test_wait_for_rabbitmq_success(self):
        # Should return immediately if socket.create_connection works
        self.module.wait_for_rabbitmq('localhost', 5672, timeout=1)
        self.mock_socket.assert_called()

    def test_wait_for_rabbitmq_timeout(self):
        # Simulate socket.create_connection always failing
        self.mock_socket.side_effect = Exception('fail')
        with self.assertRaises(RuntimeError):
            self.module.wait_for_rabbitmq('localhost', 5672, timeout=0.01)

    def test_queue_declare_and_publish(self):
        # Test that queue_declare and basic_publish are called 100 times
        mock_channel = MagicMock()
        self.mock_pika.return_value.channel.return_value = mock_channel
        # Re-execute the script logic
        with patch.object(self.module, 'wait_for_rabbitmq'):
            exec(open(MODULE_PATH).read(), self.module.__dict__)
        mock_channel.queue_declare.assert_called_with(queue='test-queue', durable=True)
        self.assertEqual(mock_channel.basic_publish.call_count, 100)

    def test_callback_acknowledges(self):
        # Test that callback prints and acknowledges
        ch = MagicMock()
        method = MagicMock()
        method.delivery_tag = 123
        properties = None
        body = b'hello world'
        self.module.callback(ch, method, properties, body)
        ch.basic_ack.assert_called_with(delivery_tag=123)
        self.mock_print.assert_any_call('Received: hello world')

if __name__ == '__main__':
    unittest.main()

