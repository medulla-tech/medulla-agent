# Plugin resetagent - Reinitialisation forcee de la base agent

## Objectif

Permettre la remise en etat complete et inconditionnelle d'un agent Medulla
dont le mecanisme de mise a jour est bloque, en boucle ou corrompu.
L'operateur declenche le reset depuis le master substitut ; l'agent repart
avec une base propre sans intervention manuelle sur la machine.

---

## Architecture : deux plugins complementaires

```
Operateur
   |
   | appel resetagent (JID cible)
   v
[plugin_resetagent - substitut]   lit file d'attente resetagent_queue.json
   |                               verifie presence machine
   | action "resetagent"
   v
[plugin_resetagent - machine]     vide img_agent
                                   leve les verrous
                                   demande descripteur frais
                                   |
                                   v
                             [mecanisme updateagent standard]
                                   tous fichiers retransferes
                                   reinstall_agent() declenche
                                   agent redemarre propre
```

---

## Comportement cote machine (pluginsmachine/plugin_resetagent.py)

Quand la machine recoit l'action `resetagent` :

1. Supprime `BOOL_DISABLE_IMG` si present (leve le verrou de mise a jour).
2. Vide completement `img_agent/` (toute la base locale de reference est effacee).
3. Recrée la structure vide `img_agent/{lib,script}/`.
4. Remet `descriptor_master` a None pour forcer une demande fraiche.
5. Envoie une demande de descripteur au master substitut.

Le mecanisme `updateagent` standard prend alors le relais :
- `img_agent` etant vide, TOUS les fichiers sont consideres manquants.
- Ils sont retransferes inconditionnellement, sans verification d'empreinte.
- Quand `img_agent` correspond au descripteur master, `reinstall_agent()` est
  appele et l'agent redémarre avec sa base completement rafraichie.

**Ce plugin ne touche jamais les fichiers de l'agent en cours d'execution.**
Il ne modifie que `img_agent` et les fichiers flag. Le redemarrage se fait
par `replicator.py` via le chemin standard, ce qui est safe meme sur un
agent partiellement corrompu.

---

## Comportement cote master substitut (pluginsmastersubstitute/plugin_resetagent.py)

### Mode appel direct

Envoyer l'action `resetagent` au substitut avec le payload :

```json
{ "jid": "pc-win11pro-3.7v7@pulse", "reason": "boucle update infinie" }
```

- Si la machine est en ligne : l'ordre de reset est envoye immediatement.
- Si elle est hors ligne : elle est ajoutee a la file d'attente JSON.

### Mode file d'attente

Creer ou modifier le fichier `resetagent_queue.json` dans le repertoire
de configuration du substitut :

```json
[
  {"jid": "pc-win11pro-3.7v7@pulse", "reason": "boucle update infinie"},
  {"jid": "pc-linux-5.lan@pulse",    "reason": "agent corrompu"}
]
```

Appeler l'action `resetagent` sans payload sur le substitut pour traiter
la file. Les machines en ligne sont traitees et retirees ; les machines
hors ligne restent en attente.

---

## Deploiement

### Copier les plugins dans la base agent (pour distribution aux machines)

```
xmpp_baseplugin/plugin_resetagent.py   (version machine)
```

### Copier le plugin substitut sur le serveur

```
/usr/lib/python3/dist-packages/pulse_xmpp_master_substitute/
  pluginsmastersubstitute/plugin_resetagent.py
```

Redemarrer le service `pulse-xmpp-master-substitute-registration`.

---

## Versionnage

| Fichier | Version | Type |
|---------|---------|------|
| `pluginsmachine/plugin_resetagent.py` | 1.0 | machine |
| `pluginsmastersubstitute/plugin_resetagent.py` | 1.0 | substitute |

---

## Limitations connues et evolutions prevues

- **Type actuel** : `machine` uniquement. A etendre a `relayserver` si besoin.
- **Fichiers .sh** non pris en compte par le mecanisme `updateagent` standard
  (le fingerprint ne couvre que `.py` et `.ps1`). A corriger en parallele.
- **Pas de confirmation de fin de reset** : le substitut n'attend pas de
  retour de la machine. Une future version pourrait ajouter un
  `plugin_resultresetagent` pour confirmer la completion.
