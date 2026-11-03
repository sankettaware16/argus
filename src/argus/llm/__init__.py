"""Phase 2: everything that touches a language model (D-012, D-074, D-075). P1, the privacy
layer: ``detect`` (identifiers in text), ``privacy`` (the model's view of a dossier,
pseudonymized) and ``egress`` (the last check before anything leaves). Nothing here calls a
model; the running Phase 1 services never import this package."""
