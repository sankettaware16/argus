"""Minimal notices: short e-mails that carry a link, a severity and a count to the people named in
the settings, through a mail relay. Nothing is sent until ``notices.enabled`` is true and a
recipient is named. ``model`` holds the kinds, deduplication and the rate limit (pure),
``triggers`` what is worth a notice, ``render`` the subject and body (fixed text and numbers only),
``mail`` the addresses, the message and the SMTP relay, ``run`` the pass."""
