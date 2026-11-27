"""Print a Splunk search that tests the account triage dashboard."""

from pathlib import Path
from xml.etree import ElementTree

from kerberos_password_spray_search import make_results


ACCOUNT = "fixture-analyst"
SID = "S-1-5-21-100-200-300-1100"
PRIMARY_HOST = "fixture-dc-01"
CLIENT_IP = "192.0.2.10"


def kerberos(offset, event_id, status, host=PRIMARY_HOST, ip=CLIENT_IP, account=ACCOUNT):
    return {
        "offset": offset,
        "host": host,
        "EventCode": event_id,
        "TargetUserName": account,
        "IpAddress": ip,
        "Status": status,
    }


def membership(offset, sid):
    return {
        "offset": offset,
        "host": PRIMARY_HOST,
        "EventCode": 4728,
        "TargetUserName": "Fixture Admins",
        "SubjectUserName": "fixture-operator",
        "MemberSid": sid,
    }


def main():
    root = Path(__file__).resolve().parents[1]
    dashboard = ElementTree.parse(root / "dashboard" / "account-triage.xml")
    query = dashboard.findtext("row/panel/table/search/query")
    if not query:
        raise SystemExit("Expected a search query in the dashboard XML.")

    _, separator, pipeline = query.strip().partition("\n| ")
    if not separator:
        raise SystemExit("Expected a pipeline in the dashboard search.")
    pipeline = pipeline.replace("$triage_account|s$", f'"{ACCOUNT}"')
    pipeline = pipeline.replace("$triage_sid|s$", f'"{SID}"')

    cases = [
        ("bad-preauth", kerberos(10, 4771, "0x18", ip=f"::ffff:{CLIENT_IP}"), 4771, -1),
        ("same-host-ip", kerberos(45, 4768, "0x0"), 4768, 35),
        ("other-ip", kerberos(50, 4768, "0x0", ip="192.0.2.11"), 4768, -1),
        ("other-controller", kerberos(55, 4768, "0x0", host="fixture-dc-02"), 4768, -1),
        ("failed-tgt", kerberos(60, 4768, "0x12"), 4768, -1),
        ("other-account", kerberos(70, 4768, "0x0", account="fixture-other"), 0, -1),
        ("selected-member", membership(75, SID), 4728, -1),
        ("other-member", membership(80, "S-1-5-21-100-200-300-1200"), 0, -1),
        ("after-ten-minutes", kerberos(611, 4768, "0x0"), 4768, -1),
    ]
    expected = [
        {
            "offset": event["offset"],
            "scenario": scenario,
            "expected_event_id": event_id,
            "expected_seconds": seconds,
        }
        for scenario, event, event_id, seconds in cases
    ]
    anchor = 'relative_time(now(), "-1h@h")'
    print(f"""{make_results(event for _, event, _, _ in cases)}
| eval _time={anchor}+offset
| {pipeline.rstrip()}
| eval offset=_time-{anchor}, actual_seconds=coalesce(seconds_since_failure, -1)
| append [ {make_results(expected)} ]
| eval fixture_key=printf("fixture:%d", round(tonumber(offset), 0))
| stats values(scenario) AS scenario count(event_id) AS results max(event_id) AS actual_event_id max(actual_seconds) AS actual_seconds max(expected_event_id) AS expected_event_id max(expected_seconds) AS expected_seconds by fixture_key
| eval actual_event_id=coalesce(actual_event_id, 0), actual_seconds=coalesce(actual_seconds, -1)
| eval status=if(isnotnull(expected_event_id) AND results=if(expected_event_id=0, 0, 1) AND actual_event_id=expected_event_id AND actual_seconds=expected_seconds, "PASS", "FAIL")
| fillnull value="unexpected" scenario
| table scenario actual_event_id expected_event_id actual_seconds expected_seconds status
| sort scenario""")


if __name__ == "__main__":
    main()
