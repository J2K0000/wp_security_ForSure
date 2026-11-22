from wp_security_forsure.scanner.checks.base import CheckResult


def has_confirmed_critical(results):
    from wp_security_forsure.__main__ import _has_confirmed_critical
    return _has_confirmed_critical(results)


def test_potential_critical_does_not_trip_exit():
    r = CheckResult("c", "T", "d", "INFO", True)
    r.add_finding("maybe bad", severity="CRITICAL", confidence="potential")
    assert has_confirmed_critical([r]) is False


def test_confirmed_critical_trips_exit():
    r = CheckResult("c", "T", "d", "INFO", True)
    r.add_finding("real", severity="CRITICAL", confidence="confirmed")
    assert has_confirmed_critical([r]) is True
