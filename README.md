# hwm-context

Public derived/materialized read-model repository for the HeroesWM autonomous development infrastructure.

Repository visibility is not a trust boundary. Authoritative project state is not stored here: contents must be rebuildable from authoritative sources, generated artifacts must carry source provenance, and trusted writes must come only from protected workflows/branches and appropriately scoped identities. Ordinary product agents are read-oriented and must not obtain write credentials merely because the repository is public.

All committed context, wiki, graph, task, claim, health, and bootstrap artifacts must be safe for full public disclosure. Tokens, cookies, browser profiles, account credentials, private keys, session data, personal data, sensitive raw evidence, and other secret-bearing material are forbidden in Git, Issues, PRs, Actions artifacts, and logs. Standard Git author/committer attribution metadata is expected to be public and is permitted; the personal-data prohibition applies to repository files and other public operational/generated surfaces.

I01 creates structure only. It does not create current state, generated bootstrap, wiki pages, graph data, claims, or historical handoff imports. PR CI uses ephemeral GitHub-hosted runners with read-only repository contents and no secrets. Trusted post-merge generation may also use GitHub-hosted runners when it is reproducible from GitHub or external immutable inputs; any local-only executor remains deferred to I11/I12 and is capability-driven rather than assumed.

<!-- disposable I08-0042 strict-context proof; never merge -->
