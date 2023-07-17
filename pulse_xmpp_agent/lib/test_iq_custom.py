#!/usr/bin/python3
# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-2.0-or-later
import unittest
from datetime import datetime, timedelta
from iq_value import iq_value


class TestIQValue(unittest.TestCase):
    def setUp(self):
        self.iq = iq_value()
        self.now = datetime.now()

    def test_ajouter_valeur_obtenir_valeur(self):
        self.iq.ajouter_valeur("cle1", "valeur1", 5)
        self.iq.ajouter_valeur("cle2", "valeur2", 10)

        valeur1 = self.iq.obtenir_valeur("cle1")
        valeur2 = self.iq.obtenir_valeur("cle2")
        valeur3 = self.iq.obtenir_valeur("cle3")

        self.assertEqual(valeur1, "valeur1")
        self.assertEqual(valeur2, "valeur2")
        self.assertIsNone(valeur3)

    def test_nettoyer_valeurs_expirees(self):
        expiration = self.now - timedelta(seconds=5)
        self.iq.dictionnaire = {
            "cle1": ("valeur1", expiration),
            "cle2": ("valeur2", expiration),
            "cle3": ("valeur3", self.now + timedelta(seconds=5)),
        }

        self.iq.nettoyer_valeurs_expirees()
        self.assertNotIn("cle1", self.iq.dictionnaire)
        self.assertNotIn("cle2", self.iq.dictionnaire)
        self.assertIn("cle3", self.iq.dictionnaire)

    def test_augmenter_temps(self):
        expiration = self.now + timedelta(seconds=5)
        self.iq.dictionnaire = {
            "cle1": ("valeur1", expiration),
            "cle2": ("valeur2", expiration),
            "cle3": ("valeur3", expiration),
        }

        self.iq.augmenter_temps(10)
        nouvelle_expiration = self.now + timedelta(seconds=15)

        self.assertEqual(self.iq.dictionnaire["cle1"][1], nouvelle_expiration)
        self.assertEqual(self.iq.dictionnaire["cle2"][1], nouvelle_expiration)
        self.assertEqual(self.iq.dictionnaire["cle3"][1], nouvelle_expiration)

    def test_afficher_cles_et_temps(self):
        expiration = self.now + timedelta(seconds=10)
        self.iq.dictionnaire = {
            "cle1": ("valeur1", expiration),
            "cle2": ("valeur2", expiration),
            "cle3": ("valeur3", expiration),
        }

        expected_output = """Clé        Temps d'expiration    Temps restant
cle1       {}   0:00:10
cle2       {}   0:00:10
cle3       {}   0:00:10""".format(
            expiration, expiration, expiration
        )

        self.assertEqual(self.iq.afficher_cles_et_temps(), expected_output)


if __name__ == "__main__":
    unittest.main()
