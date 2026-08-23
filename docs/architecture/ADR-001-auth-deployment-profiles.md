# ADR-001 — Profils de déploiement Auth

- Statut : accepté
- Date : 2026-08-23
- Issue : [#313](https://github.com/PileOuFaces/Pile_Ou_Face/issues/313)
- Contrat fournisseur : [Pile_ou_Face_auth#48](https://github.com/PileOuFaces/Pile_ou_Face_auth/issues/48)
- Implémentation Host : [#322](https://github.com/PileOuFaces/Pile_Ou_Face/pull/322), [#323](https://github.com/PileOuFaces/Pile_Ou_Face/pull/323), [#324](https://github.com/PileOuFaces/Pile_Ou_Face/pull/324), [#325](https://github.com/PileOuFaces/Pile_Ou_Face/pull/325)

## Contexte

Le Host peut être distribué par le canal SaaS officiel, sous forme de VSIX
administrée pour une entreprise, depuis les sources OSS ou dans une offre
contractuelle sans réseau. Ces artefacts ne doivent pas accepter les mêmes
sources de configuration Auth. Une URL modifiable ne doit notamment jamais
permettre à l’artefact officiel de faire confiance à une autre autorité de
licence.

## Décision

Le profil est fixé au packaging et fait partie de l’identité de l’artefact.
Quatre profils sont reconnus :

| Profil | Endpoint Auth | Modification utilisateur | `deployment_id` | Distribution |
|---|---|---:|---|---|
| `OFFICIAL_SAAS` | injecté par le build officiel | non | `official-saas` | Marketplace / Open VSX officiels |
| `MANAGED_ON_PREM` | injecté dans la VSIX entreprise | non | propre au client | canal administré privé |
| `OSS_DEVELOPMENT` | setting explicite, puis détection loopback | oui | `oss-development` ou identité découverte | sources OSS / développement |
| `AIRGAP_ENTERPRISE` | aucun | non | propre au contrat | canal privé hors-ligne |

Le masquage du champ endpoint est une propriété d’interface, pas une frontière
de sécurité. La frontière repose sur la configuration produit embarquée, la
découverte versionnée et la vérification cryptographique locale.

## Résolution de l’endpoint

Les sources sont filtrées par profil avant toute résolution :

1. `OFFICIAL_SAAS` et `MANAGED_ON_PREM` utilisent exclusivement
   `product.json`, généré lors du packaging ;
2. `OSS_DEVELOPMENT` accepte le réglage VS Code, puis une instance Auth voisine
   sur loopback, sinon ne se connecte à aucun serveur ;
3. `AIRGAP_ENTERPRISE` désactive entièrement l’Auth online.

HTTPS est obligatoire hors `localhost`, `127.0.0.1` et `::1`. Le build OSS
versionné reste neutre : aucune URL d’entreprise ou de service Pile ou Face
n’est présente dans `product.default.json`.

## Découverte et identité

Avant le login, le Host consomme :

```text
GET /.well-known/pile-ou-face-auth/v1
```

Le document de découverte publie au minimum la version majeure du protocole,
`deployment_id`, `issuer`, les audiences attendues et `jwks_uri`. Le Host
refuse une version incompatible, une origine inattendue, un
`deployment_id` différent de celui fixé par un artefact administré ou un
endpoint HTTP non-loopback.

Le serveur Auth est propriétaire du contrat. Les ajouts compatibles sont
tolérés ; toute rupture de forme ou de sémantique exige une nouvelle version
majeure et un ordre de merge Auth puis Host.

## Secrets et changement d’autorité

Les secrets VS Code sont isolés par une empreinte de :

```text
(deploymentProfile, deployment_id, normalized_origin)
```

Les tokens, clés de contenu, leases et identités d’installation ne sont jamais
copiés entre deux namespaces. Dès qu’une identité serveur vérifiée diffère de
la liaison active, l’ancien namespace est purgé et l’utilisateur est
déconnecté. Les anciennes clés globales non rattachables à une autorité sont
également supprimées, sans migration implicite.

L’ancienne URL sauvegardée dans `globalState` est supprimée dans tous les
profils. Elle peut être migrée une seule fois vers le setting VS Code dans
`OSS_DEVELOPMENT`, mais ne peut jamais surcharger un artefact administré.

## Distribution et validation

La CI prépare, vérifie et empaquette quatre VSIX distinctes. Chaque matrice
contrôle l’identité embarquée et la présence du setting endpoint uniquement
pour `OSS_DEVELOPMENT`. Les workflows de publication préparent explicitement
`OFFICIAL_SAAS` avant le Marketplace ou Open VSX.

Les tests couvrent :

- filtrage des sources, migration et HTTPS hors loopback ;
- validation du document de découverte et du `deployment_id` ;
- isolation et purge de `SecretStorage` ;
- interop réelle Host vers Auth pour l’enrollment et les leases ;
- affichage du profil, de l’origine Auth et du déploiement actif ;
- construction séparée des quatre artefacts.

## Conséquences

- Une entreprise on-prem reçoit une VSIX dédiée ; une politique dynamique
  administrateur est reportée jusqu’à l’existence d’un besoin réel et devra
  être authentifiée.
- Un serveur on-prem arbitraire n’est jamais reconnu par l’artefact SaaS.
- `AIRGAP_ENTERPRISE` reste une distribution contractuelle distincte, jamais
  un fallback runtime de `ONLINE_STANDARD`.
- Changer le serveur en développement impose une nouvelle découverte et une
  reconnexion ; cette friction est volontaire pour empêcher le rejeu de
  secrets entre autorités.
