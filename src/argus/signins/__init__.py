"""Who was behind an address (AR6, D-216): the SSO sign-ins from the internal addresses of ARGUS's
investigations, kept as accounts per address and UTC day, and read back as a probable user.

Usernames are personal data. They live in ``signin_sightings`` and in the incident report's
accounts; they are shown only to people with the ``see_logs`` capability, are never part of anything
a model reads (cloud or local), and are never written to a log line.
"""
