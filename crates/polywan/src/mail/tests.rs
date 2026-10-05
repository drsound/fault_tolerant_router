use super::*;

fn email() -> Email {
    Email {
        from: "router@example.com".into(),
        to: vec!["admin@example.com".into(), "noc@example.org".into()],
        sendmail: "/usr/sbin/sendmail".into(),
        max_per_hour: 2,
        events: vec!["path_state_changed".into()],
    }
}

fn event(message: &str) -> Event {
    Event {
        seq: 1,
        instance: "i".into(),
        timestamp: "2026-10-05T01:02:03.456Z".into(),
        kind: "path_state_changed",
        uplink: Some("a".into()),
        family: Some("ipv4"),
        old: None,
        new: None,
        reason: None,
        message: message.into(),
        test: false,
    }
}

#[test]
fn base64_follows_rfc4648_in_lines_of_76() {
    let enc = |s: &str| base64_lines(s.as_bytes());
    assert_eq!(enc(""), "");
    assert_eq!(enc("f"), "Zg==\n");
    assert_eq!(enc("fo"), "Zm8=\n");
    assert_eq!(enc("foo"), "Zm9v\n");
    assert_eq!(enc("foobar"), "Zm9vYmFy\n");
    let long = base64_lines(&[0xff; 100]);
    let lines: Vec<&str> = long.lines().collect();
    assert_eq!(lines.iter().map(|l| l.len()).collect::<Vec<_>>(), [76, 60]);
    assert_eq!(long.replace('\n', ""), "////".repeat(33) + "/w==");
}

#[test]
fn host_names_qualify_for_the_subject() {
    assert_eq!(host_suffix("router\n"), Some("router"));
    assert_eq!(host_suffix("gw-1.example.net"), Some("gw-1.example.net"));
    for bad in [
        "",
        "-router",
        "router-",
        "a..b",
        "a.",
        "r\u{e9}",
        "a b",
        "a_b",
        "x(y)",
        &"a".repeat(64),
    ] {
        assert_eq!(host_suffix(bad), None, "{bad:?}");
    }
    assert!(host_suffix(&"a".repeat(63)).is_some());
}

#[test]
fn dates_follow_rfc5322() {
    let at = |s: u64| rfc5322_date(UNIX_EPOCH + Duration::from_secs(s));
    assert_eq!(at(0), "Thu, 01 Jan 1970 00:00:00 +0000");
    assert_eq!(at(1_791_158_400 + 3723), "Mon, 05 Oct 2026 01:02:03 +0000");
    assert_eq!(at(951_782_400), "Tue, 29 Feb 2000 00:00:00 +0000");
}

#[test]
fn messages_carry_the_headers_and_no_event_text_in_them() {
    let m = Message {
        kind: Kind::Notification,
        id: message_id("abc", 7, "router@example.com"),
        date: UNIX_EPOCH,
        body: "Subject: injected\nüñí\n.\nend\n".into(),
        failures: 0,
        due: Instant::now(),
    };
    assert_eq!(m.id, "<7.abc@example.com>");
    let text = String::from_utf8(render(&m, &email(), Some("gw")).unwrap()).unwrap();
    let (head, body) = text.split_once("\n\n").unwrap();
    assert_eq!(
        head,
        "Date: Thu, 01 Jan 1970 00:00:00 +0000\nMessage-ID: <7.abc@example.com>\nFrom: router@example.com\nTo: admin@example.com,\n noc@example.org\nSubject: PolyWAN notification (gw)\nMIME-Version: 1.0\nContent-Type: text/plain; charset=UTF-8\nContent-Transfer-Encoding: base64\nAuto-Submitted: auto-generated"
    );
    assert_eq!(body, base64_lines(m.body.as_bytes()));
    assert!(body.lines().all(|l| l.len() <= 76));
    let mut test = m.clone();
    test.kind = Kind::Test;
    let text = String::from_utf8(render(&test, &email(), None).unwrap()).unwrap();
    assert!(text.contains("\nSubject: PolyWAN notification test\n"), "{text}");
}

#[test]
fn bodies_and_messages_keep_their_bounds() {
    let mut m = Message {
        kind: Kind::Notification,
        id: "<1.a@example.com>".into(),
        date: UNIX_EPOCH,
        // A multi-byte character across the cut.
        body: "ü".repeat(BODY_BYTES),
        failures: 0,
        due: Instant::now(),
    };
    let text = String::from_utf8(render(&m, &email(), None).unwrap()).unwrap();
    // The 13 octets of the marker leave an odd room: the cut drops the
    // half of a two-octet character.
    let body = "ü".repeat((BODY_BYTES - 13) / 2) + "\n[truncated]\n";
    assert!(body.len() <= BODY_BYTES);
    assert_eq!(text.split_once("\n\n").unwrap().1, base64_lines(body.as_bytes()));
    // Recipients are never truncated: a message that cannot hold them
    // fails.
    let mut many = email();
    many.to = (0..30_000).map(|i| format!("user{i}@example.com")).collect();
    m.body = "short".into();
    assert!(render(&m, &many, None).unwrap_err().contains("more than"));
}

#[test]
fn batches_retain_200_changes_and_64_kib() {
    let now = Instant::now();
    let mut b = Batch::new(now);
    for i in 0..250 {
        b.add(&event(&format!("change {i}")));
    }
    let body = b.body(Some("gw"), 0);
    assert!(body.starts_with("PolyWAN on gw reports 250 changes:\n\n"), "{body}");
    assert_eq!(body.matches("path_state_changed a ipv4: change").count(), 200);
    assert!(body.contains("50 further changes were omitted"), "{body}");
    let mut b = Batch::new(now);
    for _ in 0..20 {
        b.add(&event(&"x".repeat(10_000)));
    }
    assert_eq!((b.changes, b.omitted), (6, 14));
    assert!(b.text.len() <= BATCH_BYTES);
    // Control characters never add lines.
    assert_eq!(
        change_line(&event("a\nb\u{7}")),
        "2026-10-05T01:02:03.456Z path_state_changed a ipv4: a\\u{a}b\\u{7}\n"
    );
    assert!(
        Batch::new(now)
            .body(None, 3)
            .contains("3 notifications were suppressed")
    );
}

#[test]
fn admission_holds_a_rolling_hour_with_one_notice() {
    let hour = Duration::from_secs(3600);
    let t0 = Instant::now();
    let at = |s: u64| t0 + Duration::from_secs(s);
    let mut a = Admission::default();
    assert_eq!(a.admit(at(0), 2, hour), Admit::Yes { suppressed: 0 });
    assert_eq!(a.admit(at(10), 2, hour), Admit::Yes { suppressed: 0 });
    assert_eq!(a.admit(at(20), 2, hour), Admit::No { notice: true });
    assert_eq!(a.admit(at(30), 2, hour), Admit::No { notice: false });
    // The first admission leaves the window: one slot, and the count of
    // what was suppressed.
    assert_eq!(a.admit(at(3600), 2, hour), Admit::Yes { suppressed: 2 });
    assert_eq!(a.admit(at(3605), 2, hour), Admit::No { notice: false });
    assert_eq!(a.admit(at(3610), 2, hour), Admit::Yes { suppressed: 1 });
    assert_eq!(a.admit(at(3611), 2, hour), Admit::No { notice: false });
    // An hour after the notice, another one.
    assert_eq!(a.admit(at(3625), 2, hour), Admit::No { notice: true });
    // A larger limit after a reload applies at once.
    assert_eq!(a.admit(at(3630), 3, hour), Admit::Yes { suppressed: 2 });
}

#[test]
fn closing_batches_admits_or_suppresses() {
    let t0 = Instant::now();
    let mut mail = Mail::new("abc".into(), Times::default(), Arc::default(), Sendmail::default());
    let e = email();
    for _ in 0..4 {
        mail.add(t0, Duration::from_secs(30), &event("x"));
        assert_eq!(mail.batch.as_ref().unwrap().deadline, t0 + Duration::from_secs(30));
        mail.close_batch(t0, &e, None);
    }
    // Two notifications, one notice, the fourth suppressed silently.
    let kinds: Vec<Kind> = mail.waiting.iter().map(|m| m.kind).collect();
    assert_eq!(kinds, [Kind::Notification, Kind::Notification, Kind::Suppressed]);
    let ids: Vec<&str> = mail.waiting.iter().map(|m| m.id.as_str()).collect();
    assert_eq!(
        ids,
        ["<1.abc@example.com>", "<2.abc@example.com>", "<3.abc@example.com>"]
    );
}

#[test]
fn failures_are_retried_after_1_5_and_15_minutes() {
    let t0 = Instant::now();
    let mut mail = Mail::new("abc".into(), Times::default(), Arc::default(), Sendmail::default());
    let m = mail.message(Kind::Notification, "b".into(), &email(), t0);
    let id = m.id.clone();
    mail.wait(m);
    let mut now = t0;
    for minutes in [1, 5, 15] {
        let m = mail.take_due(now).unwrap();
        assert!(mail.take_due(now).is_none());
        mail.failed(m, now);
        let due = mail.next_due().unwrap();
        assert_eq!(due - now, Duration::from_secs(60 * minutes));
        assert!(mail.take_due(due - Duration::from_millis(1)).is_none());
        now = due;
    }
    let m = mail.take_due(now).unwrap();
    assert_eq!((m.id.as_str(), m.failures), (id.as_str(), 3));
    mail.failed(m, now);
    assert!(mail.waiting.is_empty(), "dropped after the third retry");
}

#[test]
fn waiting_messages_are_bounded_and_discarded_with_email() {
    let t0 = Instant::now();
    let mut mail = Mail::new("abc".into(), Times::default(), Arc::default(), Sendmail::default());
    for i in 0..10 {
        let m = mail.message(Kind::Notification, format!("{i}"), &email(), t0);
        mail.wait(m);
    }
    assert_eq!(mail.waiting.len(), WAITING);
    assert_eq!(mail.waiting.front().unwrap().body, "2", "the oldest evicted");
    // A retry due earlier than a new message goes first.
    let mut first = mail.waiting.pop_back().unwrap();
    first.due = t0 - Duration::from_secs(1);
    let body = first.body.clone();
    mail.wait(first);
    assert_eq!(mail.take_due(t0).unwrap().body, body);
    mail.add(t0, Duration::from_secs(30), &event("x"));
    assert_eq!(mail.discard(), WAITING - 1 + 1);
    assert!(mail.waiting.is_empty() && mail.batch.is_none());
}

#[test]
fn sendmail_runs_as_root_with_explicit_recipients() {
    let s = spec(&email(), b"m".to_vec(), Duration::from_secs(60));
    assert_eq!(s.program, std::path::PathBuf::from("/usr/sbin/sendmail"));
    assert_eq!(
        s.args,
        ["-i", "-f", "router@example.com", "admin@example.com", "noc@example.org"]
    );
    assert_eq!((s.uid, s.gid, s.capture_stdout, s.env.len()), (0, 0, false, 0));
}
