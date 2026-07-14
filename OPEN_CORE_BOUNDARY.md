# Frontière open-core

Ce dépôt (`Pile_Ou_Face`) est le **host open-source** (AGPL). Il doit rester
**dissociable de la société** : quelqu'un qui n'utilise que la partie publique
ne doit hériter d'aucun lien vers notre infrastructure commerciale.

## Règle

> Le host open-source ne contient **aucun endpoint, branding ou télémétrie**
> spécifique à la société. Il embarque des **clients de protocoles ouverts**
> (entitlement/licence, collaboration) qui, **par défaut, ne se connectent
> nulle part**. Les serveurs et le contenu premium (plugins chiffrés, SaaS
> collaboratif hébergé) vivent dans des dépôts privés et se vendent séparément.

## Comment c'est appliqué

### Couche de config produit (`extension/product.default.json` + `productConfig.ts`)

- `product.default.json` (versionné) : configuration **neutre**, toutes les
  URLs de providers vides.
- `product.json` (non versionné, cf. `.gitignore`) : overlay écrit par le
  **build commercial officiel** pour pointer vers les providers officiels.
- Tout le code « se connecter à un serveur » lit ses endpoints via
  `productConfig`, **jamais** via une constante en dur.

Conséquence : un host construit depuis la source seule ne connaît aucune URL et
ne contacte personne. Un self-hoster configure la sienne ; le build officiel
configure la nôtre.

### Auth / entitlement des plugins

- `authConfig.ts` : le défaut distant provient de `productConfig.authProviderUrl`
  (vide en OSS). Sans provider configuré (build officiel, réglage VS Code
  `pileOuFace.authServerUrl`, ou dev local détecté), la résolution renvoie une
  chaîne vide et aucune connexion n'est tentée.
- Le **moteur de déverrouillage** des plugins (`backends/plugins/runtime.py`,
  `license.py`) est déjà provider-agnostique : il déverrouille sur présence
  d'une `content_key` (`POF_CONTENT_KEY_<ID>`) **ou** d'un fichier de licence
  signé RSA-PSS. Il ne sait pas d'où vient la clé. N'importe quel éditeur peut
  chiffrer ses propres plugins et émettre ses propres licences.

### Collaboration (SaaS)

- Le **serveur** vit dans le dépôt privé `Pile_ou_Face_server`.
- Le **client** dans le host parle un **protocole ouvert**, lit son URL via
  `productConfig.collabProviderUrl` (vide en OSS), reste dormant tant qu'aucune
  URL n'est configurée, et n'embarque aucune télémétrie.

## Le test décisif

Avant d'ajouter du code réseau au host, se demander : *« un fork qui n'utilise
que l'OSS hérite-t-il d'un lien vers notre société ? »* Si oui, l'endpoint doit
passer par `productConfig` (neutre par défaut), et le contenu/serveur premium
doit vivre dans un dépôt privé.
