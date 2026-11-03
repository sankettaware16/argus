"""Minimal notices (Q-H4, plan §5 and §7.7, DQ26): short e-mails that carry a link, a severity and
a count, to the people the user names, once the user has approved the campus mail relay. Nothing
here is sent until ``notices.enabled`` is true and a recipient is named.

* :mod:`~argus.notices.model`: the five kinds, the rules of deduplication and the rate limit (pure).
* :mod:`~argus.notices.triggers`: what is worth a notice, read from ARGUS's own database.
* :mod:`~argus.notices.render`: the subject and body, built from fixed text and numbers only.
* :mod:`~argus.notices.mail`: addresses, the message and the SMTP relay.
* :mod:`~argus.notices.run`: the pass (``argus notices run``) and what a person asks about it.
"""
