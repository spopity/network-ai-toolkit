"""Log templating: what the LLM gets instead of raw log lines."""
from router_agent.summarize import (
    _template,
    group_lines,
    merge_groups,
    render_groups,
    split_by_section,
    summarize_lines,
)

LINES = [
    "Nov 14 09:00:01 RT-AX88U dropbear[100]: Bad password attempt for 'admin' from 203.0.113.5:4022",
    "Nov 14 09:00:07 RT-AX88U dropbear[101]: Bad password attempt for 'admin' from 203.0.113.9:5110",
    "Nov 14 09:01:00 wlceventd: wlceventd_proc_event(645): wl0.1: Auth 02:00:00:00:00:01, status: Successful (0)",
    "Nov 14 09:02:00 RT-AX88U miniupnpd[14714]: shutting down MiniUPnPd",
    "Nov 14 09:03:00 RT-AX88U kernel: eth0 link down",
]


def test_template_masks_variable_parts():
    t = _template("from 203.0.113.5:4022 mac 02:00:00:00:00:01 id 0xdeadbeef {\"a\": 1} took 1234ms")
    assert "203.0.113.5" not in t
    assert "02:00:00:00:00:01" not in t
    assert "<IP>" in t and "<MAC>" in t and "<HEX>" in t and "{…}" in t
    assert "1234" not in t


def test_lines_differing_only_in_ip_and_port_share_a_template():
    g = group_lines(LINES[:2])
    assert g["lines"] == 2
    assert len(g["groups"]) == 1
    grp = g["groups"][0]
    assert grp["source"] == "dropbear"
    assert grp["count"] == 2
    assert grp["values"] == ["203.0.113.5", "203.0.113.9"]
    assert grp["notable"] is False  # "Bad password" alone is not one of the problem words


def test_parses_both_syslog_formats_and_strips_function_prefix():
    g = group_lines(LINES)
    sources = [x["source"] for x in g["groups"]]
    assert sources == ["dropbear", "wlceventd", "miniupnpd", "kernel"]
    wl = g["groups"][1]
    assert not wl["template"].startswith("wlceventd_proc_event")
    assert g["window"] == ["Nov 14 09:00:01", "Nov 14 09:03:00"]


def test_notable_lines_are_ranked_first_but_shutting_down_is_routine():
    out = summarize_lines(LINES, top=10)
    first = out["messages"][0]
    assert first["source"] == "kernel"  # "link down" is notable
    assert first["notable"] is True
    upnp = next(m for m in out["messages"] if m["source"] == "miniupnpd")
    assert "notable" not in upnp


def test_render_one_off_vs_repeat_and_omitted_counts():
    out = summarize_lines(LINES, top=2)
    one_off = out["messages"][0]
    assert set(one_off) >= {"at", "message"} and "template" not in one_off and "count" not in one_off
    repeat = out["messages"][1]
    assert repeat["count"] == 2 and "template" in repeat and "example" not in repeat
    assert out["omitted"] == {"messages": 2, "lines": 2}
    assert out["distinct_messages"] == 4


def test_window_uses_min_max_across_concatenated_files():
    g = group_lines(["Nov 14 10:00:00 a: x", "Oct 30 08:00:00 a: x", "Nov 02 12:00:00 a: x"])
    assert g["window"] == ["Oct 30 08:00:00", "Nov 14 10:00:00"]


def test_merge_groups_accumulates_counts_values_and_window():
    a = group_lines(LINES[:1])
    b = group_lines(LINES[1:2] + ["Nov 15 00:00:00 RT-AX88U dropbear[1]: Bad password attempt for 'admin' from 203.0.113.7:1"])
    m = merge_groups(a, b)
    assert m["lines"] == 3
    assert len(m["groups"]) == 1
    g = m["groups"][0]
    assert g["count"] == 3
    assert g["first"] == "Nov 14 09:00:01" and g["last"] == "Nov 15 00:00:00"
    assert g["values"] == ["203.0.113.5", "203.0.113.9", "203.0.113.7"]
    assert m["window"] == ["Nov 14 09:00:01", "Nov 15 00:00:00"]


def test_merge_groups_caps_size_keeping_notable():
    acc = group_lines([f"Nov 14 09:00:00 p{i}: routine message" for i in range(10)] + ["Nov 14 09:00:00 k: error"])
    m = merge_groups({"groups": []}, acc, max_groups=3)
    assert len(m["groups"]) == 3
    assert m["groups"][0]["notable"] is True


def test_render_groups_of_empty_input():
    out = render_groups({"groups": []})
    assert out["messages"] == [] and out["lines"] == 0 and "omitted" not in out


def test_split_by_section_routes_by_process():
    out = split_by_section(summarize_lines(LINES, top=10), per_section=10)
    assert [m["source"] for m in out["security"]["messages"]] == ["dropbear"]
    assert [m["source"] for m in out["wifi"]["messages"]] == ["wlceventd"]
    assert {m["source"] for m in out["system"]["messages"]} == {"kernel", "miniupnpd"}


def test_split_by_section_reports_omitted():
    lines = [f"Nov 14 09:00:00 kernel: event type {chr(97 + i)} happened" for i in range(5)]
    out = split_by_section(summarize_lines(lines, top=10), per_section=2)
    assert len(out["system"]["messages"]) == 2
    assert out["system"]["omitted_messages"] == 3
