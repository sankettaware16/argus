"""Outside threat intel: VirusTotal, Shodan and Censys, behind one module. ``facts`` (what an
answer is and how it is said), ``providers`` (how each source is asked and read), ``eligible``
(external indicators only), ``store`` (cache, ledger, limits), ``service`` (the lookup), ``read``
(cached facts for investigations) and ``prefetch`` (the daily look-up of beacon destinations).
Nothing outside this package and the investigator's tools asks a source."""
