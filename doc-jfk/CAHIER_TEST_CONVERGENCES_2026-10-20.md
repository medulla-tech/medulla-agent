# Cahier de test des convergences

**Date de preparation : 20 octobre 2026**

**Objet : recette reelle des convergences apres rapprochement d'identite**

**Statut initial : a executer sur une machine et un groupe dedies**

## 1. Objectifs

### Complement du 21 octobre : declenchement automatique post-imaging

**Complement installe sur SPO le 21 octobre ; parcours imaging encore a executer.**
Les tests d'installation via passage console et de non-reinstallation sont
documentes dans le rapport de preuve, mais ne remplacent pas ce parcours.

- Preparer une convergence active avant l'imaging et noter ses groupes,
  sa commande et ses dernieres executions.
- Reinstaller le poste avec l'agent Medulla et un logiciel temoin absent.
  Ne pas cliquer sur replanification et ne pas desactiver/reactiver la convergence.
- Horodater la reception et l'injection reussie de l'inventaire, la
  reconciliation d'identite, la notification en file, l'evaluation MMC,
  la creation de cible et le debut effectif du deploiement.
- Verifier l'installation, le nouvel inventaire et l'absence de doublon
  lors des inventaires suivants ; couvrir aussi un UUID GLPI conserve.
- Avec une seconde machine temoin hors des notifications, verifier qu'elle
  n'est pas ajoutee par le seul traitement post-inventaire (commande loin de
  son expiration). Tester une convergence desactivee
  et une execution deja en cours.
- Mesurer la profondeur de file, la duree par lot, la charge SQL et la
  reactivite MMC avec des groupes representatifs. Ne pas assimiler le test
  local de 10 000 notifications simulees a un test de charge de 10 000 agents.

Le passage commun au cron historique (par defaut chaque heure a :42) fige
toutes les demandes presentes, sans plafond de lecture. La file conserve une
seule demande par machine, actualisee par revision. Chaque groupe de deploiement
est evalue une seule fois par convergence traitee, pour les demandes d'inventaire
et la maintenance historique. Les ajouts sont fractionnes par 1 000 cibles au
maximum, dans le meme passage sans recalcul du groupe. Tester une et dix
notifications : aucun seuil minimum n'est requis. Tester 300 000 demandes :
un seul passage doit les selectionner, sans report du au plafond precedent.
Pendant l'evaluation, injecter un inventaire de la meme machine et celui
d'une nouvelle machine : leurs demandes doivent rester apres acquittement.
Verifier que plusieurs inventaires successifs d'un poste actualisent une
seule ligne et que le groupe utilise les donnees GLPI disponibles au calcul.
Les raisons et limites de ce choix sont dans le
[document de preuve](./PREUVE_TESTS_SPO_2026-10-20.md#reprise-du-21-octobre--besoin-initial-et-choix-de-traitement-par-lots).
Le temps total inclut l'attente dans la file et le moteur de deploiement :
aucun delai universel d'une heure n'est garanti sous charge.
Les arrivees apres lecture attendent le passage suivant, sans prolonger
indefiniment l'ensemble traite. Les sous-groupes partages ne sont pas caches globalement.
Mesurer la memoire du snapshot complet et verifier que le traitement tient
dans l'heure ; sinon la cadence horaire ne peut pas etre garantie.
Sans arriere, l'attente du
prochain passage est d'environ 0 a 60 minutes. Le cron reste configure par
defaut a `42 * * * *` ; verifier le traitement des demandes meme quand la
commande de convergence est encore loin de son expiration.

### Complement : convergence negative (desinstallation)

**A executer ; non valide par les retraits manuels du 20 octobre.**

1. Utiliser un paquet temoin avec une section `uninstall` fonctionnelle et
   verifiee ; ne pas utiliser tel quel le paquet 7-Zip dont la commande de
   desinstallation est vide.
2. Configurer une convergence negative active avant la remontee du poste,
   verifier ses criteres de presence et la section `uninstall` de sa commande.
3. Avec le logiciel present, envoyer l'inventaire et attendre le passage a :42,
   sans replanifier manuellement. Verifier une seule cible ajoutee et une
   execution de desinstallation, jamais une installation.
4. Confirmer le resultat XMPP, le code de sortie et l'absence effective du
   logiciel ; envoyer l'inventaire d'absence.
5. Au passage suivant, verifier l'absence de nouvelle desinstallation.
6. Verifier aussi : poste hors du groupe (commande loin d'expiration),
   convergence desactivee et execution deja en cours, sans doublon.

Une fiche MSC `done` ne suffit pas a prouver la desinstallation. Conserver les
horodatages, parametres de section, resultats XMPP et preuves d'inventaire.

### Objectifs de la recette initiale

Ce cahier doit verifier qu'une convergence :

1. selectionne la bonne machine depuis le groupe parent ;
2. installe le logiciel attendu lorsque la machine n'est pas conforme ;
3. place la machine dans les groupes internes de convergence attendus ;
4. ne relance pas inutilement le deploiement lorsque la machine est conforme ;
5. reprend correctement apres une absence, un echec ou une desinstallation ;
6. continue a cibler la meme machine apres un inventaire et un changement
   d'identifiant GLPI ;
7. conserve les groupes et profils necessaires apres suppression puis recreation
   de la fiche GLPI ;
8. ne cree ni doublon de machine, ni doublon d'appartenance, ni commande
   incoherente.

Le cahier complete les tests locaux decrits dans le
[bilan des tests de convergence et d'inventaire](./BILAN_TESTS_CONVERGENCE_INVENTAIRE_2026-10-20.md).
Ces tests ont valide le rapprochement d'identite et la conservation des groupes,
mais pas l'execution reelle d'une convergence.

## 2. Logiciel temoin recommande

### 2.1 Choix principal : 7-Zip

Pour une machine Windows, utiliser un paquet de test **7-Zip** dont la version
est absente de la machine au debut de la recette.

Raisons du choix :

- installation et desinstallation silencieuses ;
- faible volume et faible impact ;
- aucun redemarrage normalement requis ;
- version visible dans l'inventaire et dans le registre Windows ;
- executable facilement verifiable ;
- retrait manuel simple pour tester la remise en conformite.

Le paquet doit avoir un nom non ambigu, par exemple :

```text
RECETTE-CONVERGENCE-7ZIP-<version>
```

La version exacte, l'UUID du paquet et les commandes silencieuses doivent etre
notes avant le test. Ne pas reutiliser un paquet de production susceptible
d'etre modifie pendant la recette.

### 2.2 Plan B pour une machine Linux

Si la machine cible n'est pas Windows, choisir un petit paquet sans service et
sans redemarrage, absent de la machine au depart, par exemple `jq`. Les memes
criteres s'appliquent : installation, version, inventaire et desinstallation
doivent etre objectivement verifiables.

### 2.3 Conditions imposees au paquet

Le paquet retenu doit :

- etre disponible sur le serveur de paquets et synchronise sur l'ARS cible ;
- avoir une commande d'installation idempotente ;
- retourner un code de succes exploitable par Medulla ;
- fournir une commande de verification independante de l'interface ;
- disposer d'une procedure de desinstallation connue ;
- ne pas provoquer de redemarrage, d'arret de service metier ou de perte de
  donnees ;
- ne pas etre requis par une autre application de la machine de test.

## 3. Portee et limite concernant l'imaging

Une convergence logicielle reussie valide une partie importante du parcours
post-imaging :

- retour en ligne de l'agent ;
- reception d'un inventaire ;
- identification de la machine ;
- evaluation de son appartenance au groupe parent ;
- ajout a une commande de convergence ;
- telechargement et execution du paquet ;
- suivi du resultat.

Elle ne valide pas a elle seule :

- le demarrage PXE ;
- le menu et le profil d'imagerie ;
- le partitionnement et la restauration de l'image ;
- les pilotes, le chargeur de demarrage et le premier boot ;
- la conservation de l'identite materielle pendant l'imaging ;
- la reinstallation ou la reconfiguration de l'agent apres image ;
- le rattachement au bon profil d'imagerie ;
- le delai du premier inventaire apres image.

**Conclusion de recette :** si les convergences normales passent, le moteur de
deploiement post-inventaire est bien couvert, mais un test imaging minimal reste
obligatoire avant de conclure que le parcours imaging fonctionne.

## 4. Environnement et acteurs

La recette doit etre executee sur un environnement autorise avec :

- une machine de test dediee et restaurable ;
- un compte Medulla autorise a gerer groupes, paquets et convergences ;
- un ARS en ligne et correctement associe a la machine ;
- un paquet disponible sur cet ARS ;
- un groupe parent reserve a la recette ;
- un acces en lecture aux journaux et aux bases pour constituer les preuves ;
- une sauvegarde ou un moyen de restaurer les donnees modifiees.

Ne pas supprimer ni recreer une fiche GLPI de production. Le scenario d'identite
doit viser exclusivement la machine dediee et suivre la procedure approuvee pour
l'infrastructure.

## 5. Fiche de preparation

Completer cette fiche avant toute action.

| Donnee | Valeur |
|---|---|
| Infrastructure | |
| Date et heure de debut | |
| Operateur | |
| Validateur | |
| Machine / nom DNS | |
| Systeme et version | |
| ARS / JID | |
| UUID XMPP initial | |
| ID GLPI initial | |
| UUID materiel / numero de serie | |
| ID interne Dyngroup | |
| Groupe parent de recette | |
| Groupes existants a conserver | |
| Profil d'imagerie initial | |
| Logiciel et version temoin | |
| UUID du paquet | |
| Commande de verification | |
| Commande de desinstallation | |
| Identifiant de convergence | |
| Identifiant de commande MSC | |
| Fenetre de deploiement | |

## 6. Etat initial obligatoire

Avant d'activer la convergence :

1. verifier que la machine est en ligne dans Medulla ;
2. declencher ou attendre un inventaire recent ;
3. verifier que la machine n'existe qu'une fois dans GLPI, XMPP et Dyngroup ;
4. verifier que le logiciel temoin et sa version cible sont absents ;
5. relever les appartenances aux groupes ;
6. relever le profil d'imagerie eventuel ;
7. verifier que le paquet est disponible sur l'ARS ;
8. verifier qu'aucune ancienne commande du meme paquet n'est encore active ;
9. creer le groupe parent dedie et y placer uniquement la machine de test ;
10. conserver les captures, identifiants et horodatages.

Pour 7-Zip, les controles locaux possibles sont :

```powershell
Get-ItemProperty `
  HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*, `
  HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* `
  -ErrorAction SilentlyContinue |
  Where-Object DisplayName -Like '7-Zip*' |
  Select-Object DisplayName, DisplayVersion
```

```powershell
Test-Path "$env:ProgramFiles\7-Zip\7z.exe"
```

## 7. Preuves a conserver pour chaque scenario

Pour chaque cas, conserver :

- heure de debut et de fin ;
- operateur ;
- etat initial ;
- action executee ;
- resultat attendu et resultat obtenu ;
- capture de la convergence et de ses groupes ;
- ID de commande, ID de session et etat final du deploiement ;
- extrait de journal pertinent avec horodatage ;
- resultat de la commande locale de verification ;
- inventaire avant et apres lorsque le scenario le demande ;
- anomalie et lien vers le ticket si le resultat est non conforme.

Ne pas retenir la seule couleur ou le seul message de l'interface comme preuve.
Le succes doit etre confirme au minimum par le resultat de deploiement et par
l'etat reel de la machine.

## 8. Scenarios de recette

### CT-01 - Creation inactive de la convergence

**Action**

1. creer une convergence positive entre le groupe parent et le paquet temoin ;
2. la laisser inactive ;
3. attendre au moins un cycle normal d'evaluation.

**Attendu**

- la definition de convergence existe avec le bon groupe et le bon paquet ;
- aucun deploiement ne demarre ;
- le logiciel reste absent ;
- aucune commande active ne cible la machine.

### CT-02 - Installation par convergence positive

**Action**

1. activer la convergence ;
2. lancer la replanification explicite si elle fait partie de la procedure de
   recette, sinon attendre le cycle planifie ;
3. suivre les phases jusqu'a leur terme.

**Attendu**

- la machine non conforme entre dans le groupe de deploiement ;
- une seule execution est creee pour la machine ;
- le paquet est telecharge puis installe ;
- le deploiement termine en succes ;
- la version exacte est presente sur la machine ;
- l'inventaire suivant remonte cette version ;
- la machine passe dans l'etat ou le groupe interne de conformite attendu.

### CT-03 - Idempotence sur machine conforme

**Action**

1. conserver la machine dans le groupe parent ;
2. declencher un nouvel inventaire ;
3. replanifier la convergence ;
4. attendre un cycle complet.

**Attendu**

- le logiciel reste installe dans la bonne version ;
- aucune seconde installation inutile n'est executee ;
- aucun doublon n'apparait dans les groupes internes ;
- aucun doublon de machine n'apparait dans Dyngroup ;
- la commande reste coherente et sans cible parasite.

### CT-04 - Remise en conformite apres desinstallation manuelle

**Action**

1. desinstaller manuellement le logiciel temoin ;
2. verifier localement son absence ;
3. lancer un inventaire ;
4. attendre l'actualisation des groupes ;
5. replanifier la convergence.

**Attendu**

- la machine quitte l'etat de conformite ;
- elle revient dans le groupe de deploiement ;
- une nouvelle execution est ajoutee a la convergence ;
- le logiciel est reinstalle ;
- l'inventaire final confirme la version ;
- une machine deja terminee peut donc etre remise en conformite.

### CT-05 - Machine hors ligne puis reprise

**Action**

1. retirer de nouveau le logiciel ou choisir un etat non conforme ;
2. mettre la machine hors ligne avant l'execution ;
3. activer ou replanifier la convergence ;
4. verifier l'absence de faux succes ;
5. remettre la machine en ligne.

**Attendu**

- l'etat hors ligne n'est pas presente comme un succes ;
- la cible reste reprenable ;
- au retour de l'agent, le deploiement demarre ou reprend selon la politique ;
- l'installation et l'inventaire final reussissent ;
- aucune seconde machine n'est creee.

### CT-06 - Echec controle et nouvelle tentative

Ce cas doit utiliser une methode reversible approuvee : paquet de recette avec
parametre volontairement invalide, indisponibilite temporaire du paquet ou
autre panne sans impact sur le serveur.

**Action**

1. provoquer l'echec ;
2. verifier le statut et le journal ;
3. corriger la cause ;
4. relancer ou replanifier la convergence.

**Attendu**

- l'echec est explicite et n'est pas transforme en succes ;
- la machine reste non conforme ;
- la cause est visible dans les journaux ;
- apres correction, une nouvelle tentative peut reussir ;
- le succes final correspond a une installation reelle.

### CT-07 - Desactivation et reactivation

**Action**

1. desactiver la convergence ;
2. rendre la machine non conforme ;
3. inventorier et attendre un cycle ;
4. verifier qu'aucun deploiement ne demarre ;
5. reactiver puis replanifier.

**Attendu**

- inactive, la convergence ne cree pas d'execution ;
- la definition et les donnees restent consultables ;
- reactivee, elle reprend la machine non conforme ;
- une seule execution utile est lancee.

### CT-08 - Entree tardive d'une nouvelle machine

Ce scenario peut reutiliser la machine de test en la retirant puis en la
reintegrant au groupe parent, ou utiliser une seconde machine dediee.

**Action**

1. activer la convergence avant que la machine appartienne au groupe ;
2. ajouter ensuite la machine au groupe parent ;
3. replanifier ou attendre le renouvellement de la commande.

**Attendu**

- une machine nouvellement eligibile est ajoutee a la commande ;
- les dates de la commande sont prolongees selon la configuration ;
- l'installation est executee une fois ;
- les autres machines deja conformes ne sont pas redeployees.

### CT-09 - Sortie du groupe parent

**Action**

1. retirer la machine du groupe parent ;
2. actualiser le groupe ;
3. replanifier la convergence.

**Attendu pour une convergence positive**

- aucun nouveau deploiement n'est programme pour cette machine ;
- le logiciel deja installe n'est pas supprime automatiquement ;
- les autres appartenances ordinaires de la machine ne changent pas.

### CT-10 - Convergence de desinstallation

Executer ce scenario uniquement si la polarite de desinstallation fait partie
du perimetre de recette.

**Action**

1. reinstaller et inventorier le logiciel temoin ;
2. creer ou basculer vers une convergence de desinstallation dediee ;
3. activer et suivre la commande.

**Attendu**

- seule la machine eligibile est ciblee ;
- la desinstallation termine en succes ;
- le binaire et l'entree d'inventaire disparaissent ;
- un second cycle n'execute pas de desinstallation inutile.

### CT-11 - Inventaire repete sans changement d'identite

**Action**

1. replacer la machine dans l'etat requis pour la convergence positive ;
2. executer deux inventaires successifs ;
3. relever les identifiants et appartenances apres chaque inventaire.

**Attendu**

- UUID XMPP, ID GLPI et ID interne Dyngroup restent coherents ;
- aucune appartenance n'est perdue ;
- aucune ligne de reprise d'identite ne subsiste ;
- la convergence continue a evaluer la machine ;
- aucun doublon de deploiement n'est cree.

### CT-12 - Suppression puis recreation de la fiche GLPI

Ce scenario est le controle principal du chantier de rapprochement d'identite.
Il exige une machine dediee, une sauvegarde et une autorisation explicite.

**Action**

1. noter tous les identifiants, groupes, profils et commandes ;
2. supprimer la fiche GLPI selon la procedure approuvee ;
3. provoquer un inventaire permettant la recreation ;
4. attendre les reprises de recherche prevues ;
5. verifier le rapprochement vers la nouvelle fiche active ;
6. replanifier la convergence.

**Attendu**

- l'ancienne fiche supprimee ou mise a la corbeille n'est pas reselectionnee ;
- la nouvelle fiche active est choisie par UUID materiel, MAC ou, en dernier
  recours, nom exact unique ;
- `xmppmaster.machines.uuid_inventorymachine` et `id_glpi` referencent la
  nouvelle identite ;
- la reference d'organisation AD, si elle existe, est actualisee ;
- l'identifiant interne Dyngroup conserve est celui attendu ;
- les appartenances ordinaires et le profil compatible sont conserves ;
- la file de reprise est vide apres succes ;
- la convergence retrouve la machine et atteint le resultat attendu ;
- aucune seconde machine logique ni double appartenance n'est creee.

### CT-13 - Conflit de profils

Ce scenario est reserve a un jeu de test dont les profils peuvent etre
manipules sans risque.

**Action**

1. construire le conflit de profils prevu par la recette ;
2. declencher le rapprochement d'identite ;
3. constater l'echec ;
4. supprimer le conflit ;
5. relancer un inventaire.

**Attendu**

- aucun profil n'est choisi arbitrairement ;
- les appartenances et la file de reprise sont conservees pendant le conflit ;
- l'erreur est journalisee ;
- apres resolution, le nouvel inventaire termine la reconciliation ;
- la convergence peut ensuite cibler la machine.

### CT-14 - Nettoyage et suppression de la convergence

**Action**

1. desactiver puis supprimer la convergence de recette ;
2. supprimer les groupes internes uniquement par le parcours applicatif ;
3. conserver ou desinstaller le logiciel selon la decision de fin de test.

**Attendu**

- aucune commande active orpheline ne subsiste ;
- aucune nouvelle execution n'est creee ;
- le groupe parent et les autres groupes metier restent intacts ;
- seules les donnees creees pour la recette sont retirees.

## 9. Controle imaging minimal

### IMG-01 - Reprise de convergence apres reimaging

Ce test ne doit etre execute qu'apres succes des cas CT-01 a CT-12 et sur une
machine restaurable.

**Action**

1. relever identifiants, groupes, profil et logiciel avant imaging ;
2. appliquer un profil d'imagerie approuve ;
3. verifier le premier demarrage et le retour de l'agent ;
4. attendre un inventaire complet ;
5. verifier le rapprochement d'identite et les groupes ;
6. laisser la convergence logicielle installer 7-Zip si l'image ne le contient
   pas, ou constater la conformite si la bonne version est deja presente.

**Attendu**

- la machine demarre correctement apres image ;
- l'agent revient en ligne sous l'identite attendue ;
- une seule machine logique existe ;
- le bon profil et les groupes sont retrouves ;
- la convergence voit la machine ;
- si le logiciel est absent, il est installe une fois ;
- s'il est deja conforme, aucune installation inutile n'est lancee ;
- l'inventaire final contient la bonne version.

Ce resultat permet de conclure sur le parcours post-imaging de cette machine,
mais pas sur tous les profils, modeles materiels ou systemes d'exploitation.

## 10. Controles SQL en lecture seule

Ces requetes sont des aides au diagnostic. Adapter les valeurs entre chevrons
et ne lancer aucune requete d'ecriture pendant la collecte des preuves.

### 10.1 Identite XMPP

```sql
SELECT id, jid, hostname, uuid_inventorymachine, uuid_serial_machine,
       macaddress, agenttype, groupdeploy, enabled
FROM xmppmaster.machines
WHERE hostname = '<HOSTNAME>' OR uuid_inventorymachine = '<UUID_GLPI>';
```

### 10.2 Identite et groupes Dyngroup

```sql
SELECT id, uuid, name
FROM dyngroup.Machines
WHERE uuid IN ('<ANCIEN_UUID>', '<NOUVEL_UUID>') OR name = '<HOSTNAME>';
```

```sql
SELECT m.id AS machine_id, m.uuid, m.name,
       g.id AS group_id, g.name AS group_name, g.parent_id
FROM dyngroup.Machines m
JOIN dyngroup.Results r ON r.FK_machines = m.id
JOIN dyngroup.Groups g ON g.id = r.FK_groups
WHERE m.uuid IN ('<ANCIEN_UUID>', '<NOUVEL_UUID>') OR m.name = '<HOSTNAME>'
ORDER BY m.id, g.id;
```

### 10.3 Definition de convergence

```sql
SELECT id, parentGroupId, deployGroupId, doneGroupId,
       packageUUID, commandId, active
FROM dyngroup.Convergence
WHERE parentGroupId = <ID_GROUPE_PARENT>
   OR commandId = <ID_COMMANDE>;
```

### 10.4 File de rapprochement

La file persistante est creee dans la base Dyngroup par le substitute :

```sql
SELECT xmpp_machine_id, old_uuid, new_uuid
FROM dyngroup.substitute_pending_machine_identity
WHERE xmpp_machine_id = <ID_MACHINE_XMPP>
   OR old_uuid IN ('<ANCIEN_UUID>', '<NOUVEL_UUID>')
   OR new_uuid IN ('<ANCIEN_UUID>', '<NOUVEL_UUID>')
ORDER BY xmpp_machine_id, old_uuid;
```

Apres un rapprochement reussi, cette requete ne doit retourner aucune ligne
concernant la machine. Si la table n'existe pas, le substitute deploye n'inclut
pas encore le mecanisme de reprise ou n'a pas pu l'initialiser : le scenario
doit etre marque **BLOQUE**, et non conforme par defaut.

## 11. Criteres globaux d'acceptation

La recette des convergences normales est **ACCEPTEE** seulement si :

- CT-01 a CT-09 et CT-11 a CT-12 sont conformes ;
- CT-10 est conforme lorsqu'une convergence de desinstallation est requise ;
- CT-13 est conforme lorsqu'un conflit de profils peut etre teste ;
- aucune perte d'appartenance n'est observee ;
- aucune identite supprimee n'est reselectionnee ;
- aucune machine ni appartenance en doublon n'est creee ;
- aucun echec n'est presente comme un succes ;
- l'etat local du logiciel confirme les resultats de l'interface ;
- les preuves permettent de relier machine, groupe, paquet, commande et session ;
- le nettoyage CT-14 est conforme.

La recette imaging est **ACCEPTEE POUR LE PROFIL TESTE** seulement si IMG-01 est
egalement conforme. Le succes des convergences normales ne suffit pas a lui
seul pour prononcer cette acceptation.

## 12. Fiche de resultat par scenario

| Champ | Valeur |
|---|---|
| Scenario | |
| Date / heure | |
| Operateur | |
| Etat initial | |
| Actions realisees | |
| Resultat attendu | |
| Resultat obtenu | |
| ID commande / session | |
| Preuves et journaux | |
| Verdict : Conforme / Non conforme / Bloque | |
| Anomalie associee | |
| Commentaire du validateur | |

## 13. Proces-verbal final

| Domaine | Verdict | Commentaire |
|---|---|---|
| Installation positive | |
| Idempotence | |
| Remise en conformite | |
| Reprise hors ligne | |
| Reprise apres echec | |
| Activation / desactivation | |
| Entree et sortie du groupe | |
| Desinstallation | |
| Inventaires repetes | |
| Recreation GLPI | |
| Conservation des groupes | |
| Conservation du profil | |
| Nettoyage | |
| Imaging minimal | |

**Decision finale :** ACCEPTE / ACCEPTE AVEC RESERVES / REFUSE / NON EXECUTE

**Validateur :**

**Date :**

**Reserves ou anomalies restantes :**
