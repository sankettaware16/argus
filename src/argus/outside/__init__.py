"""Outside threat intel (AR3, D-165): VirusTotal, Shodan and Censys, behind one module.

``facts`` (what an answer is and how it is said), ``providers`` (how each source is asked and read,
and the one transport that touches the network), ``eligible`` (external indicators only),
``store`` (the cache, the ledger, the limits), ``service`` (:class:`~argus.outside.service.Outside`,
the lookup), ``read`` (cached facts for investigations), ``prefetch`` (the daily look-up of beacon
destinations). Nothing outside this package and the investigator's tools asks a source, and the
pages never do.
"""
