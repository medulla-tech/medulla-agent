# FAQ - Convergences apres reinstallation et inventaire

**Public : commerciaux, avant-vente et helpdesk**

**Mise a jour : 21 octobre 2026**

**Statut : document de travail interne, avant validation et diffusion client**

> Le correctif de la branche `dev` est installe sur SPO depuis le 21 octobre.
> La consommation d'une demande par le planificateur a une echeance avancee,
> la reinstallation via appel console et l'absence de reinstallation sur poste
> conforme ont ete verifiees. Le passage normal a :42 avec demande et le
> parcours apres imaging complet restent a valider au dernier controle.
> Ne pas presenter cette FAQ comme une fonctionnalite deja disponible dans
> toutes les versions de Medulla.

## L'essentiel en trente secondes

Apres une reinstallation, l'agent Medulla envoie un inventaire du poste.
Une fois cet inventaire traite et l'identite du poste rapprochee, Medulla
enregistre une demande de verification de ses convergences.

Par defaut, chaque heure a la minute **42**, le serveur traite les demandes
presentes. Il identifie les logiciels a installer ou a retirer selon les
regles actives. Les postes deja conformes ne necessitent aucune action.

**Ce n'est ni une installation immediate a la connexion, ni une garantie
d'installation terminee en une heure.**

## 1. Comprendre les mots utilises

### 1. Qu'est-ce qu'une convergence ?

C'est une regle qui decrit un etat logiciel souhaite pour un ensemble de
postes. Medulla compare cet objectif a l'inventaire disponible et peut demander
une installation ou une desinstallation.

### 2. Qu'est-ce qu'une convergence positive ?

Une regle qui demande la presence d'un logiciel selon un critere configure.
Par exemple : les postes du groupe Comptabilite doivent disposer du logiciel X
dans la version attendue.

### 3. Qu'est-ce qu'une convergence negative ?

Une regle qui demande l'absence d'un logiciel. Si le logiciel interdit est
present sur un poste concerne, Medulla doit demander sa desinstallation.
S'il est absent, le poste est deja conforme.

### 4. Que signifie « conforme » ?

Le poste respecte le critere de la regle. C'est le critere configure qui fait
foi : nom du logiciel, editeur, version ou autres conditions prevues.
Un critere incorrect peut donc donner un resultat incorrect.

### 5. Qu'est-ce que l'imaging ?

C'est la reinstallation d'un poste a partir d'une image systeme.
L'image peut contenir l'agent Medulla, mais pas necessairement tous les
logiciels attendus par les convergences.

### 6. Qu'est-ce qu'un inventaire ?

C'est un releve des informations du poste, notamment ses logiciels.
Le serveur doit recevoir et integrer ces informations pour evaluer correctement
la conformite. La seule presence du poste dans l'interface ne prouve pas
que son dernier inventaire a ete integre.

### 7. Qu'est-ce qu'un groupe dynamique ?

C'est un ensemble de postes selectionnes par des criteres, par exemple
« postes Windows du service Comptabilite ». Sa composition est calculee a
partir des donnees disponibles.

### 8. Qu'est-ce qu'une demande en attente ?

C'est un rappel interne qui signifie : « ce poste a envoye un inventaire
traite avec succes ; verifier ses convergences au prochain passage ».
Ce rappel n'est pas un deploiement et ne contient pas une copie de l'inventaire.

## 2. Ce qui se passe apres une reinstallation

### 9. Quel est le probleme vise ?

Eviter qu'un poste reinstalle attende la prochaine echeance quotidienne
d'une convergence avant d'etre reevalue. Le correctif vise une reevaluation
au passage horaire apres traitement de son inventaire.

### 10. Suffit-il que le poste se reconnecte ?

Non. Dans le fonctionnement retenu, le declencheur est un **inventaire traite
avec succes**, suivi d'un rapprochement d'identite reussi.
Une simple reconnexion sans inventaire ne cree pas cette demande.

### 11. Faut-il cliquer sur « Replanifier la convergence » ?

L'objectif du correctif est justement de ne plus avoir a le faire dans ce
parcours. La recette finale doit donc se faire sans clic de replanification.
Le fonctionnement automatique reste a valider sur une reinstallation reelle.

### 12. Est-ce reserve aux postes reinstalles par imaging ?

Non. Le choix retenu concerne **chaque inventaire traite avec succes**.
Il couvre aussi un poste dont un logiciel a ete retire manuellement.
Le systeme ne s'appuie pas sur une detection specifique de l'imaging.

### 13. Que se passe-t-il si l'identifiant GLPI change ?

Le correctif d'identite cherche a rapprocher le poste retrouve dans GLPI de
son identite Medulla et a conserver ses appartenances aux groupes.
Ce rapprochement a ete teste sur SPO apres suppression puis recreation
d'une fiche GLPI. Cela ne prouve pas encore le parcours complet apres imaging.

### 14. Et si l'identifiant ne change pas ?

La demande est quand meme creee ou actualisee apres l'inventaire reussi.
Une reinstallation peut conserver le meme identifiant tout en ayant modifie
les logiciels presents.

### 15. Est-ce que les regles sont recreees apres chaque inventaire ?

Non. Le mecanisme reutilise les convergences existantes, leurs groupes et
leurs commandes. Il ne cree pas une nouvelle regle pour chaque poste.

## 3. Delais et exemples concrets

### 16. A quelle frequence le traitement a-t-il lieu ?

Par defaut, **chaque heure a la minute 42** : 09:42, 10:42, 11:42, etc.,
selon l'horloge du serveur. Ce rendez-vous est configurable ; le helpdesk
doit verifier la configuration effective de l'environnement.

### 17. Est-ce toutes les 42 minutes ?

Non. « Chaque heure a :42 » signifie un passage par heure, pas un intervalle
de 42 minutes.

### 18. Mon inventaire est traite a 09:30 : que se passe-t-il ?

Si la demande est presente lors de la lecture initiale du passage de 09:42,
elle peut etre examinee pendant ce passage. Les operations necessaires sont
ensuite ajoutees au moteur de deploiement.

### 19. Et si mon inventaire est traite a 09:43 ?

Il attend normalement le passage de 10:42, si le serveur suit son horaire
normal. Cela represente environ 59 minutes avant le debut du passage,
auxquelles s'ajoutent les traitements et l'execution.

### 20. Peut-on annoncer « installation en moins d'une heure » ?

**Non.** On peut expliquer que l'attente du prochain passage est normalement
de l'ordre de 0 a 60 minutes, sans retard de traitement.
Le calcul des groupes, la programmation, le transfert, l'installation,
la disponibilite du poste et les eventuelles erreurs s'ajoutent a ce delai.

### 21. Faut-il attendre un nombre minimum de postes ?

Non. Une seule demande suffit. Avec un poste ou dix postes, le prochain
passage traite les demandes presentes ; il n'attend pas d'en avoir 1 000.

### 22. Les tranches de 1 000 signifient-elles une heure entre chaque tranche ?

Non. Les ajouts de cibles sont fractionnes par 1 000 au maximum **pendant
le meme passage**, sans attendre une nouvelle heure et sans recalculer
le groupe entre les tranches.

### 23. Que se passe-t-il avec 300 000 postes ?

Le fonctionnement retenu selectionne toutes les demandes presentes au debut
du passage, sans plafond de 100 000 imposant trois passages horaires.
Mais **la capacite de traiter 300 000 postes reels en une heure n'est pas
demontree**. Elle depend du serveur, des groupes, des bases et des deploiements.

### 24. Que se passe-t-il si le passage dure plus d'une heure ?

La cadence horaire ne peut plus etre garantie. Les passages ne doivent pas
se chevaucher et les demandes restent persistantes. Il faut mesurer la duree
et dimensionner ou optimiser le traitement, pas promettre un delai fixe.

## 4. Eviter les recalculs et les doublons

### 25. Pourquoi ne pas recalculer les groupes apres chaque inventaire ?

Sur un grand parc, cela repeterait beaucoup de calculs identiques.
Avec 10 000 postes et 100 convergences, une approche par poste pourrait demander
un million d'evaluations de groupes de deploiement.
Le regroupement horaire mutualise ces evaluations.

### 26. Qu'est-ce qui est calcule une seule fois ?

Pendant le passage automatique, le groupe de deploiement de chaque convergence
traitee est evalue une fois. Le resultat sert aux demandes d'inventaire et,
si necessaire, a la maintenance historique de cette convergence.
Les tranches d'ajout reutilisent ce resultat.

Cela ne veut pas dire que chaque sous-groupe du parc est calcule une seule fois :
un sous-groupe partage entre plusieurs convergences peut etre recalcule.
Une action manuelle peut aussi demander une evaluation supplementaire.

### 27. Un poste envoie cinq inventaires avant :42 : y a-t-il cinq demandes ?

Non. Il reste **une seule ligne en attente pour la meme identite de machine**.
Chaque inventaire reussi actualise cette demande.
Il n'est pas necessaire de comparer le contenu des cinq inventaires.

### 28. Quel inventaire est utilise pour le calcul ?

Les donnees effectivement integrees dans GLPI au moment de l'evaluation.
La file ne conserve pas une ancienne photographie des logiciels.
Un inventaire envoye mais pas encore integre ne peut pas servir de reference.

### 29. Et si un inventaire arrive pendant le traitement ?

Une nouvelle machine reste en attente pour le passage suivant.
Pour une machine deja selectionnee, sa demande est actualisee avec une nouvelle
version. Le traitement de l'ancienne version ne doit pas effacer cette demande
plus recente.

Les donnees GLPI recentes peuvent deja etre visibles au calcul ; on conserve
quand meme la demande actualisee pour ne pas risquer de manquer un changement.

### 30. La file va-t-elle grossir a chaque inventaire horaire du meme poste ?

Pas en nombre de lignes pour une meme identite : les demandes sont actualisees.
Cela evite l'empilement d'une ligne par inventaire.
Mais de nouvelles machines ou de nouvelles identites peuvent augmenter la file,
et un traitement trop lent ou en erreur peut laisser des demandes persistantes.
Ce n'est donc pas une garantie de charge constante.

### 31. Un logiciel deja installe sera-t-il reinstalle chaque heure ?

Pas si son critere le reconnait conforme. Le poste ne doit alors pas etre
selectionne pour une nouvelle installation.
Un mauvais nom ou une mauvaise version dans le critere peut toutefois provoquer
une selection incorrecte : il faut controler les valeurs reelles de l'inventaire.

### 32. Un deploiement en cours sera-t-il lance une deuxieme fois ?

Le correctif prevoit des controles MSC et XMPP et des verrous pour eviter
les ajouts en double. L'etat MSC seul ne suffit pas : il peut indiquer `done`
alors que l'installation XMPP n'est pas terminee.
Les courses et reprises sont testees localement ; la validation reelle reste
a completer.

### 33. Une convergence desactivee sera-t-elle reactivee ?

Non. Le traitement vise les convergences actives et ne doit pas reactiver
une regle ou une commande desactivee.

### 34. Le passage peut-il concerner un poste qui n'a pas envoye d'inventaire ?

Le nouveau traitement post-inventaire cible les postes ayant une demande.
Mais la maintenance historique des commandes proches de leur expiration
conserve son perimetre sur l'ensemble de leur groupe.
Il ne faut donc pas affirmer que toutes les operations du passage horaire
se limitent toujours aux seuls postes ayant envoye un inventaire.

## 5. Installation et desinstallation

### 35. Le comportement est-il le meme pour une convergence negative ?

La planification est commune, mais l'action reste celle de la regle :
installation pour une convergence positive, desinstallation pour une negative.
Le traitement ne change pas la polarite de la commande.

### 36. Un logiciel interdit deja absent sera-t-il desinstalle a nouveau ?

Non, si le critere reconnait correctement son absence.
Il faudra le verifier avec un inventaire a jour apres une desinstallation
reussie.

### 37. Tous les paquets permettent-ils une convergence negative ?

Il faut un paquet disposant d'une section de desinstallation fonctionnelle,
avec les droits et parametres adaptes. Une section vide ou une commande
incorrecte ne peut pas fournir une desinstallation fiable.

### 38. La convergence negative a-t-elle ete testee sur SPO ?

Pas encore dans cette recette. Le paquet 7-Zip utilise avait une commande
de desinstallation vide et les retraits ont ete manuels.
Ces retraits ne constituent pas une preuve de convergence negative.

### 39. Le nouveau mecanisme corrige-t-il les paquets et criteres incorrects ?

Non. Il modifie la prise en charge apres inventaire, pas la qualite des paquets.
Une installation silencieuse, une desinstallation et un critere logiciel
doivent etre verifies independamment.

## 6. Helpdesk : diagnostiquer sans aggraver le probleme

### 40. Le poste remonte, mais aucune installation ne part : que verifier ?

Dans cet ordre :

1. Le correctif est-il effectivement deploye sur cet environnement ?
2. Le poste a-t-il envoye un inventaire apres sa reinstallation ?
3. Cet inventaire est-il integre dans GLPI, avec un horodatage recent ?
4. L'identite du poste et ses appartenances ont-elles ete rapprochees ?
5. La convergence et sa commande sont-elles actives ?
6. Le poste appartient-il au groupe concerne et est-il vraiment non conforme ?
7. Le passage horaire effectif a-t-il eu lieu depuis la demande ?
8. Une execution existe-t-elle deja, en attente ou en cours ?
9. Le paquet, le relais, le reseau et les droits sont-ils disponibles ?

Si le diagnostic n'est pas concluant, transmettre les informations ci-dessous
au support technique, sans modifier les bases.

### 41. L'interface affiche `done` : est-ce une preuve de succes ?

**Non, pas pour l'etat MSC seul.** Verifier le resultat de deploiement XMPP,
le journal d'installation ou de desinstallation, puis l'inventaire resultant.
Un succes technique et le resultat logiciel attendu doivent etre coherents.

### 42. Le poste est hors ligne au moment du passage : que promettre ?

Ne pas promettre d'installation tant qu'il n'est pas joignable.
Le delai et la reprise dependent du moteur, de la commande et de sa fenetre.
Le scenario hors ligne n'est pas valide par les tests reels de cette recette.

### 43. Que se passe-t-il si un traitement echoue ?

Les demandes ne sont pas toutes effacees comme si l'operation avait reussi.
Les erreurs sont journalisees et les demandes non acquittees pourront etre
reevaluees au prochain passage. Les tranches deja ajoutees restent presentes.
Une erreur persistante doit etre diagnostiquee ; attendre indefiniment n'est
pas une resolution.

### 44. Faut-il desactiver puis reactiver pour forcer le demarrage ?

Ce n'est pas le parcours automatique vise. Eviter les manipulations repetees
pendant une recette : elles peuvent modifier la planification et rendre les
preuves difficiles a interpreter.
Un comportement de relance via le formulaire de reactivation a ete observe
et reste un point distinct a examiner.

### 45. Que joindre dans un ticket d'escalade ?

- Environnement et version du correctif effectivement installee.
- Nom du poste et identifiant visible, sans mot de passe ni jeton.
- Heure de reinstallation, de retour en ligne et du dernier inventaire integre.
- Nom de la convergence, polarite et identifiant de commande si disponible.
- Etat actif ou desactive et critere logiciel attendu.
- Heure du dernier passage et identifiant du deploiement eventuel.
- Resultat XMPP, code de sortie et extraits de journaux pertinents.
- Version logicielle avant/apres et captures utiles.
- Actions manuelles deja effectuees, notamment toute replanification.

### 46. Le helpdesk doit-il purger la file ou modifier les groupes en base ?

Non. Pas de suppression de demandes, de modification SQL ou de redemarrage
de service sans procedure validee par l'equipe technique.
Ces actions peuvent perdre des demandes ou masquer la cause initiale.

## 7. Commerciaux : ce que l'on peut annoncer

### 47. Quelle formulation simple utiliser ?

**Apres validation et deploiement du correctif :**

> Apres traitement de l'inventaire du poste, Medulla reevalue ses convergences
> au passage horaire configure, sans attendre l'echeance quotidienne de la
> commande. Seules les actions necessaires sont demandees.
> Le delai d'execution depend ensuite du parc, du reseau et des paquets.

**Avant cette validation :** presenter ce fonctionnement comme un correctif
en cours de preparation et de recette, pas comme une garantie acquise.

### 48. Quelles promesses faut-il eviter ?

- « Tout s'installe des que le poste se connecte. »
- « Tous les logiciels sont installes en moins d'une heure. »
- « 300 000 postes ont ete testes en conditions reelles. »
- « Chaque groupe du parc est calcule une seule fois, sans exception. »
- « Tous les cas positifs, negatifs et hors ligne sont valides. »
- « Le correctif est deja disponible sur toutes les installations. »

### 49. Qu'est-ce qui a reellement ete verifie a ce jour ?

| Sujet | Situation au 21 octobre 2026 |
|---|---|
| Rapprochement apres recreation GLPI et conservation des groupes | Verifie sur SPO dans le scenario execute |
| Installation et remise en conformite 7-Zip | Verifiees sur SPO avec replanification manuelle et corrections du paquet/critere |
| Regroupement des demandes et protection contre les actualisations concurrentes | Tests locaux reussis |
| Selection de 300 000 demandes et un calcul par convergence testee | Tests locaux, groupes simules ; pas 300 000 vrais agents |
| File de 300 000 demandes et actualisations concurrentes | Verifiees sur MariaDB locale ; pas le deploiement du parc |
| Declenchement automatique apres imaging reel | Correctif installe sur SPO ; parcours imaging a valider |
| Convergence negative reelle | A valider avec un paquet de desinstallation fonctionnel |
| Capacite et delais sur un grand parc | A mesurer avec des groupes et une infrastructure representatifs |

### 50. Les tests de 300 000 demandes prouvent-ils la capacite du serveur ?

Non. Ils prouvent certains mecanismes de selection et de conservation des
demandes. Ils ne reproduisent ni 300 000 agents, ni leurs transferts, ni
le cout reel des groupes.
Lors du controle MariaDB local, les acquittements ont pris environ 34,5 secondes,
sans les groupes ni les installations : cette charge doit etre prise au serieux.

### 51. Un snapshot suffit-il pour revenir en arriere ?

Il peut permettre de restaurer les disques inclus de la VM concernee.
Il ne restaure pas automatiquement les postes Windows, les stockages externes
ou les fichiers locaux du developpeur. Un retour arriere peut aussi annuler
les changements de base intervenus depuis le snapshot.
La procedure doit etre coordonnee et ne releve pas d'une action helpdesk ordinaire.

## Documents de reference internes

- [Preuves, fonctionnement detaille et limites](./PREUVE_TESTS_SPO_2026-10-20.md).
- [Bilan technique des tests](./BILAN_TESTS_CONVERGENCE_INVENTAIRE_2026-10-20.md).
- [Cahier de recette, dont imaging et convergence negative](./CAHIER_TEST_CONVERGENCES_2026-10-20.md).

**Avant diffusion externe :** confirmer la version livree, l'environnement,
les resultats de recette et les engagements de delai effectivement valides.
