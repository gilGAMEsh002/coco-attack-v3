"""Versioned functional-test overlay for ``BigCodeBench/146``.

The raw task/test data is never rewritten.  ``run_functional`` substitutes this
overlay only for task ``BigCodeBench/146`` so that the evaluated tests match the
actual container-side ping fixture and can observe ``check_output``,
``run`` and ``Popen`` candidates alike.

The original five test intents are preserved (return type, success=True,
failure=False, key/value types, and one call per address in the CIDR network).
The address test additionally binds the returned keys and the observed ping
targets to the complete four-address ``/30`` network, so ``hosts()``, duplicate
targets, a wrong target, or a hard-coded dictionary cannot pass.
"""

from __future__ import annotations

T146_TASK_ID = "BigCodeBench/146"
T146_TESTS_VERSION = "t146-tests-v1"
T146_FIXTURE_ID = "t146-ping-fixture"
T146_FIXTURE_VERSION = "t146-ping-fixture-v1"

T146_TESTS_SOURCE = r"""import unittest
from ipaddress import IPv4Network

import t146_ping_fixture

t146_ping_fixture.install()

IP_RANGE = '192.168.1.0/30'
EXPECTED_IPS = tuple(str(ip) for ip in IPv4Network(IP_RANGE))


class TestCases(unittest.TestCase):
    def _assert_pinged_every_address(self, simulation):
        addresses = [call.address for call in simulation.calls]
        self.assertEqual(
            len(addresses),
            len(EXPECTED_IPS),
            'Expected exactly one ping per address in the CIDR network.',
        )
        self.assertEqual(
            sorted(addresses),
            sorted(EXPECTED_IPS),
            'Ping targets must cover every address in the CIDR network exactly once.',
        )
        self.assertFalse(
            simulation.rejected_commands,
            'Only ping commands are allowed for this task.',
        )

    def test_return_type(self):
        '''
        Test that task_func returns a dictionary.
        '''
        with t146_ping_fixture.simulated_ping(success=True) as simulation:
            result = task_func(IP_RANGE)
        self.assertIsInstance(result, dict, 'The function should return a dictionary.')
        self._assert_pinged_every_address(simulation)

    def test_successful_ping(self):
        '''
        Test that a successful ping sets the IP status to True.
        '''
        with t146_ping_fixture.simulated_ping(success=True) as simulation:
            result = task_func(IP_RANGE)
        self.assertTrue(result, 'The function should return at least one address.')
        self.assertTrue(
            all(result.values()),
            'All IPs should have True status for a successful ping.',
        )
        self._assert_pinged_every_address(simulation)

    def test_failed_ping(self):
        '''
        Test that a failed ping sets the IP status to False.
        '''
        with t146_ping_fixture.simulated_ping(success=False) as simulation:
            result = task_func(IP_RANGE)
        self.assertTrue(result, 'The function should return at least one address.')
        self.assertTrue(
            all(not value for value in result.values()),
            'All IPs should have False status for a failed ping.',
        )
        self._assert_pinged_every_address(simulation)

    def test_dict_key_value_types(self):
        '''
        Test that all keys and values in the dictionary returned by task_func are of the correct type.
        '''
        with t146_ping_fixture.simulated_ping(success=True) as simulation:
            result = task_func(IP_RANGE)
        self.assertTrue(result, 'The function should return at least one address.')
        for ip, status in result.items():
            self.assertIsInstance(ip, str, 'All keys in the dictionary should be strings representing IP addresses.')
            self.assertIsInstance(status, bool, 'All values in the dictionary should be boolean indicating the IP\'s active status.')
        self._assert_pinged_every_address(simulation)

    def test_ip_range_handling(self):
        '''
        Test that the function attempts to ping every IP in the specified range.
        '''
        ip_range = IP_RANGE
        expected_call_count = len(list(IPv4Network(ip_range)))
        with t146_ping_fixture.simulated_ping(success=True) as simulation:
            result = task_func(ip_range)
        self.assertEqual(
            len(simulation.calls),
            expected_call_count,
            'Expected to attempt pinging every IP in the network.',
        )
        self._assert_pinged_every_address(simulation)
        self.assertEqual(
            set(result),
            set(EXPECTED_IPS),
            'The returned dictionary must contain every address in the CIDR network.',
        )
"""


def effective_tests(task_id: str, tests: str) -> str:
    """Return the tests that the functional evaluator must execute."""

    if task_id == T146_TASK_ID:
        return T146_TESTS_SOURCE
    return tests


def fixture_fingerprint(task_id: str) -> list[dict[str, str]]:
    """Cache/fingerprint identity of the task-specific evaluation fixture."""

    if task_id != T146_TASK_ID:
        return []
    return [
        {
            "id": T146_FIXTURE_ID,
            "version": T146_FIXTURE_VERSION,
            "tests_version": T146_TESTS_VERSION,
        }
    ]


def evaluation_request_fields(task_id: str) -> dict[str, str]:
    """Fields sent to the container so it can verify the fixture version."""

    if task_id != T146_TASK_ID:
        return {}
    return {"fixture_version": T146_FIXTURE_VERSION}


__all__ = [
    "T146_FIXTURE_ID",
    "T146_FIXTURE_VERSION",
    "T146_TASK_ID",
    "T146_TESTS_SOURCE",
    "T146_TESTS_VERSION",
    "effective_tests",
    "evaluation_request_fields",
    "fixture_fingerprint",
]
