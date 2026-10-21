# Bilan des tests - convergence et rapprochement apres inventaire

**Date du bilan : 20 octobre 2026**

**Depot : medulla-agent ; branche : dev**

**Revision fonctionnelle de reference : `f351743a`**

**Version du plugin resultinventory : 1.21**

## 1. Synthese

**Etat au 21 octobre, avant commit :** complement installe sur SPO vers 09:39.
Une demande a ete consommee par le planificateur a une echeance temporairement
avancee ; le cron a ete restaure a :42. Le nouveau passage invoque en console
a reinstalle 7-Zip (deploiement 31 reussi), puis acquitte de nouvelles demandes
sans reinstallation sur poste conforme. Le regroupement des inventaires
rapproches a egalement ete observe. Au dernier controle, une demande attendait
le passage normal de 10:42 : ne pas presenter ce passage comme deja valide.
Le parcours apres imaging reel, les convergences negatives et la charge des
groupes reels restent a valider. Voir les horodatages dans le document de preuve.
Les mentions de preparation locale ci-dessous decrivent l'etape anterieure au
deploiement, pas l'etat courant de SPO.

**Mise a jour du 21 octobre : le probleme initial n'est pas encore valide comme
resolu.** Il s'agit du declenchement automatique apres imaging, sans attente
quotidienne. La recette SPO du 20 octobre a valide la reconciliation et des
installations avec replanification manuelle, pas ce declenchement automatique.
Un complement local sur `dev` est en preparation : notifications persistantes
apres inventaire reussi : une seule demande par machine, actualisee par revision.
Le passage historique a :42 fige toutes les demandes presentes, sans plafond
de 100 000, meme si une seule demande est presente.
Chaque groupe de deploiement est evalue une seule fois par convergence traitee
et par passage ; ce resultat est partage avec la maintenance historique.
Les ajouts sont fractionnes par 1 000 cibles maximum dans le meme passage,
sans recalcul du groupe entre les tranches. Ainsi 300 000 demandes presentes
n'imposent plus trois passages horaires. Un acquittement conditionne par
l'identifiant et la revision preserve les inventaires arrives pendant le
traitement, y compris pour une machine deja en cours de traitement.
Sans arriere, l'attente du prochain
passage est d'environ 0 a 60 minutes, puis viennent les calculs et deploiements.
Il ne s'agit pas d'une garantie de capacite pour 300 000 agents : memoire,
charge reelle, temps de traitement et sous-groupes partages restent a mesurer.
Un passage depassant une heure ne peut pas tenir la cadence horaire. Le cron
historique configurable reste inchange ; aucune tache supplementaire a une
ou dix minutes n'est conservee.
Le mecanisme vise les convergences positives **et negatives** : il reutilise
le groupe de deploiement et la commande existants, donc conserve la section
`install` ou `uninstall`. Une convergence negative ne doit retirer le logiciel
que lorsqu'il est present selon son critere. **Ce cas n'est pas encore valide
en recette reelle** : la desinstallation du paquet 7-Zip de test etait vide,
et les retraits du 20 octobre ont ete manuels.
Les choix, limites et raisons sont detailles dans la
[reprise du document de preuve](./PREUVE_TESTS_SPO_2026-10-20.md#reprise-du-21-octobre--besoin-initial-et-choix-de-traitement-par-lots).
Les versions, resultats et conclusions historiques ci-dessous concernent
la revision `f351743a`, pas ce complement encore non deploye.

Le chantier vise a conserver le rattachement d'une machine et ses appartenances
aux groupes lorsque son identifiant GLPI change apres un inventaire, notamment
apres suppression puis recreation de sa fiche.

Les validations finales executees sont :

| Campagne | Resultat | Portee |
|---|---|---|
| Suite automatisee inventaire et entites | **50 tests reussis** | SQLite, methodes reelles extraites et plugin charge avec dependances simulees |
| Chainage sur MariaDB locale | **7 scenarios reussis** | Methodes reelles GLPI 10, facade, XMPP et Dyngroup sur copies des sauvegardes |
| Premiere campagne locale MariaDB | **6 scenarios reussis** | Transactions et reprises Dyngroup sur copie du schema et des donnees restaurees |
| Campagne isolee sur le serveur spo, avant suspension des acces | **6 scenarios reussis** | Schema temporaire, structure reelle, donnees synthetiques |
| Compilation Python et controle du diff | **Reussis** | Modules modifies et tests ; `git diff --check` |
| Diagnostics de l'editeur sur les fichiers controles | **Aucune erreur signalee** | Ne remplace pas une execution complete du service |
| Deploiement sur spo, le 20 octobre a 14:59 | **Installation et demarrage verifies** | Revision `f351743a`, plugin 1.21, GLPI/XMPP/Dyngroup actifs et connexion XMPP etablie |
| Suite sur spo apres installation | **50 tests reussis** | Tests pointant sur les fichiers effectivement installes, avec bases SQLite isolees et dependances simulees |

**Conclusion : validation locale concluante sur le rapprochement d'identite,
la conservation des appartenances et les reprises sur erreur. Correctif installe
sur spo et demarrage valide ; validation de bout en bout sur une machine reelle
encore a effectuer. Details du deploiement et du retour arriere en section 10.**

Les nombres ci-dessus ne doivent pas etre additionnes en un nombre de tests
uniques : plusieurs campagnes rejouent les memes comportements.

## 2. Perimetre et comportement attendu

- L'injection d'inventaire est consideree comme acquise pour ce chantier :
  son succes n'est pas certifie par ces tests.
- Apres l'attente initiale de 15 secondes, recherche GLPI par UUID materiel,
  puis MAC ; au maximum quatre tentatives avec trois intervalles de 5 secondes.
- En dernier recours, recherche par nom exact, uniquement si le resultat est unique.
- Le choix de l'implementation GLPI reste porte par la facade `Glpi`.
- La file persistante `substitute_pending_machine_identity` conserve les anciens
  UUID avant modification de l'identite XMPP.
- La reconciliation Dyngroup conserve les appartenances, fusionne les liens
  redondants et ne recree pas les appartenances qui n'existent plus.
- Des profils d'imagerie incompatibles provoquent un signalement et une
  annulation transactionnelle, sans choix automatique d'un profil.
- Une nouvelle reception d'inventaire permet de reprendre les liens en attente.
- Aucune nouvelle semantique de convergence positive ou negative n'est livree.

Le moteur de convergence n'a pas ete modifie par ce chantier. Le maintien des
appartenances permet aux regles existantes de continuer a retrouver la machine ;
cela ne constitue pas une preuve d'execution d'une installation.

## 3. Versions et environnements

### 3.1 Suite locale automatisee

La validation finale complete a ete executee avec :

- Python **3.14.4** ;
- SQLAlchemy **1.4.54**, dans un environnement virtuel isole ;
- PyMySQL **1.2.3** pour les acces MariaDB ;
- SQLite pour les 50 tests de la suite.

Un premier environnement local utilisait SQLAlchemy 2.1.5. Des executions
partielles avaient reussi, mais la suite complete y presentait des echecs et
erreurs dont le caractere preexistant n'avait pas ete rigoureusement etabli.
Il ne faut donc pas les presenter comme une validation complete reussie,
ni comme la preuve de defauts nouveaux. La suite complete a ensuite ete
rejouee avec succes sous SQLAlchemy 1.4.54, plus proche du runtime substitute.
La compatibilite globale du service avec SQLAlchemy 2 n'est pas validee.

Les tests extraient certaines methodes reelles par AST pour eviter de charger
l'ensemble des dependances du serveur. Le plugin est charge avec des modules
runtime simules. Ce dispositif valide la logique visee, mais pas l'activation
complete du service et de tous ses connecteurs.

### 3.2 Bases locales issues des sauvegardes

- MariaDB locale : **11.8.6** ; acces local sous le compte de developpement.
- Sauvegardes du **20 octobre 2026**, fichiers `dyngroup.sql.gz`,
  `glpi.sql.gz` et `xmppmaster.sql.gz`.
- Version GLPI lue dans la sauvegarde : **10.0.17**.
- Les bases locales de destination etaient absentes avant restauration.
- Les bases systeme `mysql` et `sys` n'ont pas ete restaurees.

| Base restauree | Tables et vues | Donnees de reference observees |
|---|---:|---|
| dyngroup | 15 | 2 machines, 2 appartenances ordinaires, aucun profil affecte |
| glpi | 426 | 4 ordinateurs |
| xmppmaster | 135 | 5 machines |

Les donnees de reference comportent 3 machines XMPP reliees a une fiche GLPI,
et 2 entrees Dyngroup reliees a une fiche GLPI. Ces nombres decrivent le jeu
de sauvegarde utilise, pas une mesure de couverture d'un parc.

Precautions appliquees :

- controle d'integrite gzip des trois archives ;
- examen des directives de schema, proprietaires SQL, triggers et evenements ;
- remplacement des proprietaires SQL `root`/`mmc` par le compte local ;
- import des **12 evenements XMPP en etat DISABLED**, et verification
  qu'aucun evenement importe n'est actif ;
- adaptation du fuseau de session `Europe/Paris` vers `+00:00` pour l'import :
  la base locale ne dispose pas des tables de fuseaux correspondantes ;
- aucune modification du fuseau global ni activation du planificateur ;
- aucun service Medulla, envoi XMPP ou deploiement lance par ces campagnes.

L'import XMPP a initialement ete interrompu par l'absence du fuseau nomme ;
il a ensuite ete repris avec succes. Les archives originales n'ont pas ete
modifiees.

### 3.3 Campagne historique isolee sur spo

Cette campagne a eu lieu **avant la consigne d'arret des acces a spo**.

- MariaDB **10.11.19**, Python **3.11.2**, SQLAlchemy **1.4.46**,
  PyMySQL **1.0.2**.
- Schema temporaire `medulla_identity_test_20261020_0910`.
- Copie de la structure des tables, sans copie des lignes de production ;
  insertion de donnees synthetiques.
- Execution des methodes Dyngroup en cours de developpement, extraites par AST.
- Aucun code deploye, service redemarre ou commande de convergence executee.
- Schema temporaire supprime en fin de campagne ; suppression verifiee.

Apres la consigne d'arret, les campagnes suivantes ont ete exclusivement locales.

## 4. Inventaire detaille des 50 tests automatises

Source : [test_resultinventory_entity_sync.py](../test/test_resultinventory_entity_sync.py).
Tous les tests ci-dessous sont passes lors de l'execution finale.
Les sous-cas par version ou mode ne sont pas comptes comme des tests distincts.

### 4.1 Entites, orchestration inventaire et gestion des erreurs - 34 tests

| Test | Controle |
|---|---|
| `test_missing_target_triggers_full_sync_including_root` | Synchronisation complete si entite cible absente, racine incluse |
| `test_identical_has_two_targeted_reads_without_lock_or_writes` | Etat identique : lectures ciblees, sans verrou ni ecriture |
| `test_name_difference_corrects_all_and_preserves_internal_ids` | Correction des noms sans changement des identifiants internes |
| `test_complete_name_only_difference` | Detection d'une difference de nom complet |
| `test_manual_and_repeated_calls` | Appels manuels et repetes |
| `test_root_zero_is_target_not_forced_full_sync` | Entite racine 0 traitee comme une cible valide |
| `test_orphan_destination_is_preserved` | Conservation des entites destination orphelines |
| `test_missing_source_is_error_without_global_sync` | Source absente : erreur, sans synchronisation globale abusive |
| `test_source_unavailable_does_not_trigger_sync` | Source indisponible : pas de synchronisation |
| `test_invalid_ids_do_not_query` | Rejet des identifiants invalides avant requete |
| `test_invalid_source_names_abort_before_writing` | Noms source invalides : arret avant ecriture |
| `test_name_length_boundaries` | Limites de longueur des noms |
| `test_duplicate_destination_rejected` | Rejet des doublons destination |
| `test_busy_lock_does_not_write_or_release_foreign_lock` | Verrou occupe : aucune ecriture ni liberation du verrou d'un tiers |
| `test_lock_failure` | Echec d'acquisition du verrou |
| `test_recheck_avoids_redundant_sync_and_uses_fresh_snapshot` | Relecture apres verrouillage et prevention d'une synchronisation redondante |
| `test_write_failure_rolls_back_and_releases_lock` | Erreur d'ecriture : rollback et liberation du verrou |
| `test_release_failure_invalidates_connection` | Invalidation de connexion si liberation du verrou impossible |
| `test_python_interruption_releases_lock_and_returns_connection` | Nettoyage apres interruption Python |
| `test_all_glpi_versions_and_facade_read_effective_entity` | Lecture de l'entite effective via les huit implementations et la facade |
| `test_invalid_glpi_entity_is_reported` | Signalement d'une entite GLPI invalide |
| `test_plugin_calls_database_methods_directly` | Appels aux methodes de base prevues par le plugin |
| `test_already_correct_uuid_reaches_sync_in_all_modes` | UUID deja correct : poursuite en modes forward, module et both |
| `test_failed_machine_lookup_does_not_sync` | Echec du rapprochement : pas de synchronisation d'entite |
| `test_missing_machine_exception_is_reported_without_entity_sync` | Machine introuvable : signalement sans synchronisation d'entite |
| `test_machine_lookup_retries_then_uses_unique_hostname` | Trois attentes de reprise avant secours par nom unique |
| `test_machine_lookup_raises_when_hostname_fallback_is_ambiguous` | Nom ambigu : refus du rapprochement |
| `test_registry_continues_after_sync_error` | Poursuite de la collecte registre apres erreur d'entite |
| `test_dyngroup_conflict_is_reported_and_registry_continues` | Conflit Dyngroup signale, collecte registre et entites poursuivies |
| `test_retry_link_is_persisted_before_xmpp_uuid_update` | Ordre : persistance du lien, reference AD, puis UUID XMPP |
| `test_queue_failure_does_not_lose_old_xmpp_uuid` | File indisponible : ancien UUID XMPP conserve |
| `test_xmpp_update_failure_is_not_reported_as_success` | Echec XMPP non presente comme un succes |
| `test_organization_failure_keeps_old_xmpp_uuid_for_retry` | Echec AD : pas d'ecriture XMPP, nouvelle tentative possible |
| `test_plugin_identity_and_version` | Nom du plugin et version 1.21 |

Les verrous MySQL de la partie SQLite sont simules : les cas de verrous ne
constituent pas un test de concurrence reelle entre plusieurs workers MariaDB.

### 4.2 Recherches GLPI multiversions - 2 tests

Versions : Glpi84, Glpi92, Glpi93, Glpi94, Glpi95, Glpi100, Glpi110, Itsmng21.

| Test | Controle |
|---|---|
| `test_recreated_machine_ignores_deleted_and_template_records` | Selection de la fiche active avec meme UUID materiel ; exclusion des fiches supprimees et modeles ; resultat vide si aucune fiche active |
| `test_imaging_lookup_is_exact_and_filters_inactive_rows_in_all_versions` | Nom exact ; exclusion des fiches supprimees/modeles ; recherche transverse en contexte imaging ; maintien du filtre d'entite pour les autres contextes |

### 4.3 Dyngroup et file persistante - 14 tests

| Test | Controle |
|---|---|
| `test_reads_and_updates_machine_name_cache` | Lecture et mise a jour du nom en cache |
| `test_uuid_change_preserves_internal_id_and_links` | Changement d'UUID avec conservation de l'identifiant interne et des liens |
| `test_merge_unions_groups_and_identical_profiles_and_is_repeatable` | Union des groupes, dedoublonnage des profils identiques, idempotence |
| `test_conflicting_profiles_leave_all_rows_unchanged` | Profils incompatibles : aucune modification persistante |
| `test_target_only_profile_moves_to_preserved_source_id` | Transfert du profil cible sur l'identifiant source conserve |
| `test_existing_target_is_kept_when_source_is_missing` | Source absente : conservation de la cible existante |
| `test_database_failure_rolls_back_membership_merge` | Erreur SQL : annulation de la fusion |
| `test_missing_cache_does_not_recreate_memberships` | Cache absent : aucune recreation d'appartenance |
| `test_pending_survives_conflict_and_restarts_until_resolved` | Lien conserve apres conflit et reconnexion, puis reprise apres resolution |
| `test_second_uuid_change_preserves_all_pending_sources` | Changements successifs : conservation des anciens UUID en attente |
| `test_multiple_pending_sources_merge_existing_machine_entries` | Fusion de plusieurs sources deja presentes en cache |
| `test_sql_failure_preserves_pending_and_memberships` | Echec de suppression de file : rollback des liens et conservation de la file |
| `test_later_pending_conflict_rolls_back_all_reconciliations` | Conflit tardif : annulation de toutes les fusions de la transaction |
| `test_pending_target_mismatch_does_not_modify_memberships` | Cible devenue differente : refus de modification des appartenances |

## 5. Campagnes MariaDB

### 5.1 Six scenarios historiques sur spo

Tous reussis dans le schema temporaire decrit en section 3.3 :

1. Fusion des identites avec conservation des groupes et de la regle synthetique.
2. Repetition de la reconciliation sans doublons.
3. Conflit de profils sans modification des donnees.
4. Persistance du lien apres reconnexion, puis reprise apres resolution du conflit.
5. Changements successifs d'UUID.
6. Erreur SQL forcee et rollback transactionnel.

Ces tests n'ont pas execute une convergence ni recu un inventaire reel.

### 5.2 Six scenarios sur copie locale des tables restaurees

Tous reussis :

1. Changement d'UUID, conservation des appartenances, puis repetition.
2. Fusion des deux entrees du dump sans perte de groupes.
3. Conflit de profils ajoute pour le test, reconnexion et resolution.
4. Changements successifs avec maintien des sources en attente.
5. Erreur forcee a la suppression de file et rollback complet.
6. Cible de file differente : donnees inchangees.

Le schema temporaire `test_spo_identity_20261020` a ete supprime apres ces
tests. Les trois bases restaurees de reference ont ete conservees.

Controle complementaire dans la copie XMPP restauree : une transaction a modifie
l'UUID d'une machine ; le trigger a bien mis a jour `id_glpi`. Le rollback a
ensuite restitue les deux valeurs initiales, verifiees par requete.

### 5.3 Sept scenarios de chainage local

Copies reutilisables conservees :
`test_spo_chain_xmpp`, `test_spo_chain_dyngroup`, `test_spo_chain_glpi`.

Le script local utilise les methodes reelles extraites du depot :
recherche GLPI 10 et facade, mise a jour XMPP, reference AD et reconciliation
Dyngroup. Le trigger de mise a jour XMPP est copie et adapte au schema de test.
La table `organization_ad` du dump etant vide, une reference synthetique est
ajoutee pour verifier son remplacement.

Pour permettre l'ajout d'une fiche recreee sans toucher a la sauvegarde,
la vue `glpi_computers_pulse` est materialisee en table dans la copie de test.
Les contraintes de `Results` et `ProfilesResults` sont conservees ; la table
`Groups` est copiee sans ses dependances externes non necessaires aux scenarios.
Ce jeu ne reproduit donc pas toutes les contraintes et integrations du serveur.

| Scenario | Resultat controle |
|---|---|
| UUID materiel puis inventaire repete | Identite XMPP, `id_glpi`, reference AD, UUID Dyngroup coherents ; groupes preserves ; file vide |
| Secours par MAC | Requete GLPI reelle et chainage coherent ; les MAC proviennent de la base XMPP locale de reference, lue seulement |
| Secours par nom | MAC neutralisees, temporisations simulees ; methode GLPI reelle par nom exact et chainage coherent |
| Echec AD puis nouvel inventaire | Premier passage en erreur, ancien UUID XMPP conserve, reprise reussie |
| Conflit de profils puis reconnexion | XMPP actualise, liens et file preserves pendant le conflit, reprise reussie apres resolution |
| Machine supprimee puis recreee | Ancienne fiche dans la corbeille et nouvelle fiche active avec meme UUID materiel ; selection du nouvel ID et conservation des groupes |
| Regle de convergence synthetique | Regle inchangee ; machine toujours rattachee au groupe utilise par la regle apres changement d'UUID |

**Les sept scenarios passent.** Le dump ne contient aucune ligne dans
`Convergence` : le dernier scenario utilise donc une regle synthetique dans la
copie de test, pas une regle de production existante. Aucun moteur de
deploiement n'est lance.

## 6. Defauts reproduits pendant les tests et corrections

| Defaut | Reproduction | Correction | Validation apres correction |
|---|---|---|---|
| Recherche par nom bloquee en contexte imaging | Appel d'un filtre d'entite absent dans GLPI 10 | Alignement sur le traitement du contexte imaging de la recherche MAC ; autres contextes inchanges | Scenario MariaDB et test des huit versions |
| Reference AD non reprise apres erreur | UUID XMPP deja remplace, reference AD encore ancienne au passage suivant | Reference AD mise a jour avant l'UUID XMPP, apres persistance du lien de reprise | Scenario MariaDB et test d'echec/reprise AD |
| Fiche GLPI supprimee selectionnee | Ancienne fiche retournee a la place de la nouvelle avec meme UUID materiel | Exclusion des fiches supprimees et modeles dans les huit implementations | Echec reproduit avant correction sur MariaDB et huit versions, puis 50 tests et 7 scenarios reussis |

Autres ajustements du dispositif de test, sans correction fonctionnelle associee :

- utilisation des parametres du client local pour l'authentification PyMySQL,
  sans afficher les identifiants secrets ;
- copie des colonnes non generees de `machines` ;
- mode SQL de session adapte a l'import des valeurs historiques du dump ;
- environnement SQLAlchemy 1.4 isole pour les methodes ORM historiques.

## 7. Tracabilite des changements

| Commit local | Objet |
|---|---|
| `48b9aff0` | `feat(substitute): add dyngroup cache access for inventory` |
| `a82d4808` | `fix(substitute): persist dyngroup identity reconciliation` |
| `fbbb487b` | `fix(inventory): preserve AD retries and hostname fallback` |
| `f351743a` | `fix(convergence): ignore deleted GLPI identities after inventory` |

Avant le deploiement decrit en section 10, ces quatre commits etaient sur `dev`,
non pousses et non deployes. Ils restent non pousses apres ce deploiement.
Les executions intermediaires ont notamment valide des selections
de 14, 21, 24, 25 puis 20 tests selon le lot cible, ainsi qu'une execution
des 13 tests Dyngroup alors presents. Elles ont ete suivies par une execution
complete de 49 tests, puis de **50 tests** apres ajout du cas de recreation.
Ces selections ne sont pas des campagnes independantes a additionner.

Les controles `py_compile`, `git diff --check` et les hooks de commit ont
reussi. Des avertissements Python sur des sequences d'echappement historiques
et un avertissement de deprecation SQLAlchemy 2 restent visibles ; ils ne sont
pas traites dans ce chantier et n'ont pas empeche les executions finales.

## 8. Rejouer les validations

Depuis la racine du depot, avec un environnement contenant les dependances :

```bash
python test/test_resultinventory_entity_sync.py
```

L'environnement de validation finale utilise SQLAlchemy 1.4.54 et requests.
Le runner de tests integre de l'editeur n'avait pas decouvert ces tests
unittest ; ils ont ete executes directement avec Python.

Pour ne rejouer que les recherches GLPI et Dyngroup :

```bash
python test/test_resultinventory_entity_sync.py \
  TestGlpiSetupUuidLookup TestGlpiHostnameLookup TestDyngroupAccess
```

Le script de chainage MariaDB est conserve localement sous le nom
`test_local_inventory_chain.py` dans les artefacts de session de developpement,
avec son environnement virtuel `mariadb-test-venv`. Il n'est pas inclus dans
le depot et n'est donc pas distribue avec ce document. Il suppose une socket
MariaDB locale et les parametres du client local ; il reinitialise uniquement
ses bases `test_spo_chain_*` et ne doit pas etre lance sur une infrastructure
de production.

Les premiers scripts temporaires des campagnes de six scenarios ont ete
supprimes apres execution. Ce document restitue leurs resultats observes ;
il ne remplace pas des journaux bruts signes, qui n'ont pas ete constitues
pour l'ensemble du developpement.

## 9. Limites et recette restante

Le cahier d'execution detaille de cette recette est disponible dans le
[cahier de test des convergences](./CAHIER_TEST_CONVERGENCES_2026-10-20.md).

Les tests realises ne certifient pas encore :

- la reception XMPP d'un inventaire emis par une machine reelle ;
- le succes de l'injection d'inventaire, ni son delai reel de visibilite ;
- l'efficacite en conditions reelles des 15 secondes d'attente et des reprises :
  les temporisations sont neutralisees dans les tests automatises ;
- la synchronisation d'entites sur une source federee reelle : le dump local
  ne contient pas la vue `xmppmaster.local_glpi_entities` ; sur spo, sa lecture
  a ete verifiee apres deploiement, mais pas encore une correction d'entite ;
- l'execution effective d'une convergence et le resultat d'une installation ;
- la concurrence entre plusieurs workers, les gros volumes et les performances ;
- l'ensemble des environnements GLPI historiques : leurs requetes ciblees sont
  testees sur SQLite, le chainage MariaDB utilise seulement GLPI 10.

Le demarrage complet du substitute et la creation de la table avec le compte
applicatif sont maintenant verifies sur spo (section 10).

Recette reelle a effectuer sur le serveur maintenant autorise pour les tests :

1. Choisir une machine et une convergence de test dediees, avec etat initial connu.
2. Noter ses identifiants XMPP/GLPI/Dyngroup, groupes et profil d'imagerie.
3. Executer un vrai inventaire et verifier le rattachement sans changement d'ID.
4. Supprimer puis recreer sa fiche GLPI via le parcours d'inventaire approuve.
5. Verifier selection de la fiche active, reference AD, `id_glpi`, noms et groupes.
6. Verifier absence de lien en attente apres succes, puis repetition sans doublon.
7. Sur jeu dedie, provoquer un conflit de profils, verifier le signalement et
   la conservation des liens, puis la reprise apres resolution et nouvel inventaire.
8. Executer la convergence de test et controler son resultat sur la machine.
9. Consigner dates, versions deployees, resultats attendus/obtenus et journaux.

**Statut de livraison : correctif deploye sur spo, demarrage et regressions verifies ;
recette fonctionnelle reelle restante.
Ce document n'est pas un proces-verbal de recette de production.**

## 10. Deploiement controle sur spo - 20 octobre 2026

### 10.1 Autorisation, reference et sauvegardes

L'utilisateur a autorise le deploiement et les tests apres creation d'un
instantane Proxmox de la VM **107 (spo)**, observe termine avec le statut `OK`.
Le retour arriere Proxmox n'a pas ete execute pour le verifier.

- Source : branche `dev` de `medulla-agent`, revision
  `f351743a9fc758fd2ebcf6858b9c900f20d45c18`.
- Etat initial : plugin `resultinventory` **1.18**, GLPI **10.0.17**.
- Etat livre : plugin **1.21** ; aucun paquet ni dependance installe.
- Runtime confirme : Python **3.11.2**, SQLAlchemy **1.4.46**, PyMySQL **1.0.2**,
  MariaDB **10.11.19**.
- Stockage observe depuis la VM : racine et repertoire MariaDB sur `/dev/sda1`.
  Cela ne remplace pas un controle de la couverture des disques dans Proxmox.

Repertoire prive conserve sur spo :
`/root/medulla-tests/convergence-20261020-dev-f351743a/`.
Il contient :

- `files-before.tar.gz` : arborescence complete du substitute installe et
  configuration `/etc/pulse-xmpp-agent-substitute`, avec metadonnees ;
- `databases-before.sql.gz` : dump des bases `dyngroup`, `glpi`, `xmppmaster`,
  routines, evenements et triggers compris ;
- manifestes SHA-256, liste des fichiers livres et releves avant/apres ;
- sources de preparation et journal `installed-tests.log`.

Le service d'inventaire a ete arrete avant la sauvegarde. Le dump a ete realise
avec `--lock-all-tables`, puis son integrite gzip et les sommes SHA-256 ont ete
verifiees. Les deux archives ont egalement ete copiees hors de la VM, dans
l'espace prive de la session de developpement, et leurs sommes reverifiees.
Ces sauvegardes contiennent des donnees et identifiants sensibles : elles ne
sont pas commitees. Leur restauration n'a pas ete executee.

### 10.2 Fichiers et configuration modifies

**14 fichiers Python** ont ete installes depuis la revision indiquee :

- [agentmastersubstitute.py](../pulse_xmpp_master_substitute/agentmastersubstitute.py) ;
- [configuration.py](../pulse_xmpp_master_substitute/lib/configuration.py) ;
- [module Dyngroup](../pulse_xmpp_master_substitute/lib/plugins/dyngroup/__init__.py) ;
- [facade GLPI](../pulse_xmpp_master_substitute/lib/plugins/glpi/__init__.py)
  et les huit implementations `Glpi84`, `Glpi92`, `Glpi93`, `Glpi94`, `Glpi95`,
  `Glpi100`, `Glpi110`, `Itsmng21` ;
- [plugin resultinventory](../pulse_xmpp_master_substitute/pluginsmastersubstitute/plugin_resultinventory.py) ;
- [module XMPP](../pulse_xmpp_master_substitute/lib/plugins/xmpp/__init__.py).

Le module XMPP est un prerequis de la version 1.19 : la synchronisation des
entites, deja presente dans `dev`, etait absente du serveur. Le diff a confirme
que son ajout ne remplace aucune adaptation propre a spo. Les fichiers GLPI
et le plugin initiaux correspondaient a la revision connue anterieure a cet ajout.

Dans `agent_master_substitute_inv.ini.local` uniquement :

- activation de `xmpp, glpi, dyngroup` ;
- ajout de `[dyngroupdatabase]`, cible locale `dyngroup`, avec le compte `mmc`
  existant et ses identifiants recuperes localement, sans les afficher ;
- conservation du texte initial et verification que toutes les autres valeurs
  effectives de configuration restent identiques ;
- permissions de cet override ramenees a `0600`, proprietaire `root`.

Le fichier de configuration d'exemple du depot n'a pas remplace celui de spo.
Seul `pulse-xmpp-master-substitute-inventory.service` a ete arrete puis demarre.
Les bibliotheques remplacees sont partagees par les substitutes ; les autres
services n'ont pas ete redemarres.

### 10.3 Modification de base appliquee au deploiement

Une seule table ajoutee : **`dyngroup.substitute_pending_machine_identity`**.
Creation par le vrai module applicatif avec le compte `mmc`, moteur **InnoDB** :

| Colonne | Definition |
|---|---|
| `xmpp_machine_id` | `INT NOT NULL` |
| `old_uuid` | `VARCHAR(64) NOT NULL` |
| `new_uuid` | `VARCHAR(64) NOT NULL` |
| Cle primaire | `(xmpp_machine_id, old_uuid)` |

Aucune structure de table existante n'a ete modifiee. La comparaison de la liste
des tables avant/apres montre uniquement cet ajout. A la verification, la file
est vide ; les comptes restent a **2 Machines**, **2 Results**,
**0 ProfilesResults**, **5 machines XMPP**. Ces comptes ne prouvent pas a eux seuls
l'absence de changement de contenu.

Aucune suppression/recreation de fiche GLPI, modification volontaire de
groupe/profil, ni commande de convergence n'a ete effectuee a ce stade.
Les prochains inventaires reels pourront effectuer les mises a jour prevues.

### 10.4 Verifications executees

| Controle | Resultat observe |
|---|---|
| Suite locale avant livraison | 50 tests passes, SQLAlchemy 1.4.54 |
| Suite en preparation sur spo, avant installation | 50 tests passes, SQLAlchemy 1.4.46 |
| Suite sur les fichiers effectivement installes | 50 tests passes en 15,138 secondes |
| Compilation et import des modules installes | Reussis ; plugin 1.21 et prerequis d'entites disponibles |
| Comparaison des 14 fichiers par SHA-256 | Tous identiques aux sources preparees depuis `dev` |
| Activation GLPI, XMPP, Dyngroup | Reussie dans le vrai service |
| Connexion de `master_inv@pulse` | Etablie le 20 octobre a 14:59:53 |
| Service apres controles | `active/running`, PID 5055, `NRestarts=0` |
| Lecture de `local_glpi_entities` reelle | Reussie ; moteur FEDERATED, 1 ligne source et 1 ligne destination |

Les 50 tests executent la logique installee mais utilisent SQLite et des
dependances simulees : ils ne constituent pas un inventaire reel ni une
validation de convergence. La lecture de la source FEDERATED ne prouve pas
encore la correction d'une entite par le service.

Le runner de tests de l'editeur n'a pas decouvert la suite. Un premier appel
`unittest` avec le chemin de module `test.test_resultinventory_entity_sync`
n'a pas importe la suite dans l'environnement local ; l'execution par
`unittest discover -s test -p test_resultinventory_entity_sync.py` a ensuite reussi.

Controle premerge : **A SURVEILLER**, sans erreur bloquante observee au demarrage.
Les references de conventions citees par les instructions du depot sont absentes
a sa racine (anomalie documentaire preexistante, faible) ; aucun changement hors
perimetre n'a ete fait pour les creer. La recette de bout en bout reste requise.

### 10.5 Retour arriere

Pour retrouver l'etat de la VM avant les tests, le point de retour principal
reste l'instantane Proxmox cree avant deploiement :

1. Arreter proprement la VM 107 pendant la fenetre de restauration.
2. Dans Proxmox, selectionner l'instantane d'avant les tests, puis
   **Retour en arriere** ; ne pas selectionner un ancien instantane historique.
3. Demarrer la VM et verifier les services et l'etat initial.

Ce retour annule egalement les donnees legitimes recues depuis l'instantane.
Il ne remet pas les postes clients, ni les stockages externes non inclus,
dans leur etat anterieur.

Les archives fichiers/SQL sont un secours distinct. Leur utilisation exige
une restauration coordonnee, services ecrivains arretes, et le traitement
explicite de la nouvelle table et du nouveau module absents des archives.
Un import SQL seul ou un simple redemarrage ne remet pas tout en etat.
Ne pas restaurer les trois bases pendant que les autres services y ecrivent.

## 11. Premier inventaire reel apres deploiement

Le 20 octobre 2026, l'utilisateur a declenche un inventaire sur
`pc-win11pro-2`. L'etat initial avait ete enregistre a **15:04:34**, puis
le resultat controle a **15:06:33**, apres le delai de recherche du plugin.

- Reception par le substitute a **15:05:55**.
- Journal d'identite runtime : plugin **1.21**, configuration GLPI de spo.
- Journal d'injection : `mode=forward forward_done=True module_done=False`.
- GLPI confirme `last_inventory_update = 2026-10-20 15:05:55` sur la fiche **6**.
- Identite XMPP conservee : machine **84**, `UUID6`, `id_glpi=6`.
- Identite Dyngroup conservee : machine **2**, `UUID6`, nom `pc-win11pro-2`.
- Appartenance conservee : ligne `Results` **2**, groupe **5**.
- Machine temoin `pc-win11pro-3` inchangee sur les champs controles :
  XMPP **87**, `UUID5`, fiche Dyngroup **1**, appartenance **1** au groupe **5**.
- File de reprise vide ; aucune erreur dans les nouvelles lignes du journal
  d'inventaire observees. Service `active/running`, `NRestarts=0`.

Le premier controle immediat ne montrait pas encore de reception : l'inventaire
a ete recu lors de l'attente suivante. Ce delai n'est pas une erreur du correctif.

Les releves avant/apres et le journal sont conserves dans le repertoire prive
du deploiement sur spo : `windows-before-first-inventory.tsv`,
`windows-after-first-inventory.tsv`, `windows-first-inventory.log`.

**Resultat : premier inventaire reel recu et fiche GLPI actualisee, sans perte
des identifiants ni de l'appartenance controlee.** Ce passage n'a pas change
l'identifiant GLPI : il ne valide pas encore le scenario de recreation de fiche,
la reprise sur conflit, ni une execution effective de convergence.

## 12. Recreation GLPI reelle et conservation du groupe

Le 20 octobre, apres suppression de la fiche GLPI de `pc-win11pro-2` par
l'utilisateur, le controle a **15:16:20** a confirme l'absence effective de
l'ancienne fiche **6** (et non une simple mise a la corbeille). XMPP et Dyngroup
conservaient encore `UUID6` et l'appartenance initiale.

L'inventaire suivant a ete recu a **15:17:15** par le plugin **1.21**.
Le controle SQL a **15:18:59** montre :

- nouvelle fiche GLPI active **9**, meme UUID materiel,
  `last_inventory_update=2026-10-20 15:17:15` ;
- machine XMPP **84** conservee, `uuid_inventorymachine=UUID9`, `id_glpi=9` ;
- machine Dyngroup **2** conservee, UUID actualise de `UUID6` a `UUID9` ;
- ligne `Results.id=2` et groupe **5** conserves ;
- aucune entree en attente dans la file de reprise ;
- temoin pro3 inchange sur ses identifiants et son appartenance controles ;
- service `active/running`, `NRestarts=0`, sans erreur observee dans
  l'extrait du journal du scenario.

**Verdict : conforme pour la recreation reelle et la conservation du groupe.**
Aucun profil n'etait affecte : ce test ne valide ni sa conservation, ni les
conflits de profils, ni l'execution effective d'une convergence. Le cas
d'une ancienne fiche conservee en corbeille reste distinct et non execute ici.

Le detail avant/apres, les journaux reels et les noms des pieces brutes sont
consignes dans la [preuve des tests SPO](./PREUVE_TESTS_SPO_2026-10-20.md),
section « Test 2 ». La repetition d'un inventaire sur la nouvelle fiche reste
a effectuer pour verifier la stabilite.

## 13. Inventaire repete apres recreation

L'utilisateur a relance un inventaire sans suppression supplementaire.
Reception reelle le 20 octobre a **15:21:41**, plugin **1.21** ;
controle des donnees a **15:22:11**, apres traitement :

- GLPI **9** conserve, dernier inventaire actualise a **15:21:41** ;
- XMPP **84**, `UUID9`, `id_glpi=9`, conserves ;
- Dyngroup **2**, `UUID9`, appartenance **2** au groupe **5**, conserves ;
- une seule fiche pour pro2 dans les selections GLPI/XMPP/Dyngroup et une seule
  appartenance observee, sans doublon ;
- file de reprise vide, temoin pro3 inchange sur les elements controles ;
- service `active/running`, `NRestarts=0`, aucune erreur dans l'extrait observe.

**Verdict : conforme pour la stabilite apres recreation lors de ce passage.**
Les journaux exacts, limites et pieces brutes figurent dans la
[preuve des tests SPO](./PREUVE_TESTS_SPO_2026-10-20.md), section « Test 3 ».
L'execution effective d'une convergence reste a tester.
