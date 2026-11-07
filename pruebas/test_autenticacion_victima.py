"""
Pruebas de la defensa en el sentido víctima -> servidor: el servidor solo
registra pkV si está firmada por la clave de firma de esa víctima, obtenida
antes del intercambio (confianza_victimas/<idV>.pem).
"""

import tempfile
import unittest
from pathlib import Path

from Crypto.PublicKey import RSA

from comun.firmas import firmar_clave
from comun.archivos import nombre_seguro
import servidor.servidor as srv


class PruebasAutenticacionVictima(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.firma_victima = RSA.generate(2048)
        cls.pkv = RSA.generate(2048).publickey()
        cls.pkm = RSA.generate(2048).publickey()
        cls.firma_mitm = RSA.generate(2048)

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.original = srv.CARPETA_CONFIANZA
        srv.CARPETA_CONFIANZA = Path(self.tmp.name)
        (srv.CARPETA_CONFIANZA / "v-1.pem").write_bytes(
            self.firma_victima.publickey().export_key()
        )

    def tearDown(self):
        srv.CARPETA_CONFIANZA = self.original
        self.tmp.cleanup()

    def test_acepta_pkv_firmada(self):
        firma = firmar_clave(self.firma_victima, "victima", "v-1", self.pkv)
        srv.autenticar_clave_victima("v-1", self.pkv, firma)  # no lanza

    def test_rechaza_firma_ausente(self):
        with self.assertRaises(ValueError):
            srv.autenticar_clave_victima("v-1", self.pkv, None)

    def test_rechaza_clave_sustituida(self):
        firma = firmar_clave(self.firma_victima, "victima", "v-1", self.pkv)
        with self.assertRaises(ValueError):
            srv.autenticar_clave_victima("v-1", self.pkm, firma)

    def test_rechaza_firma_del_intermediario(self):
        firma = firmar_clave(self.firma_mitm, "victima", "v-1", self.pkm)
        with self.assertRaises(ValueError):
            srv.autenticar_clave_victima("v-1", self.pkm, firma)

    def test_rechaza_rol_incorrecto(self):
        firma = firmar_clave(self.firma_victima, "servidor", "v-1", self.pkv)
        with self.assertRaises(ValueError):
            srv.autenticar_clave_victima("v-1", self.pkv, firma)

    def test_rechaza_victima_sin_clave_de_confianza(self):
        firma = firmar_clave(self.firma_victima, "victima", "v-2", self.pkv)
        with self.assertRaises(ValueError):
            srv.autenticar_clave_victima("v-2", self.pkv, firma)

    def test_rechaza_idv_con_ruta(self):
        with self.assertRaises(ValueError):
            srv.validar_id("../otro")


class PruebasNombreSeguro(unittest.TestCase):

    def test_quita_carpetas(self):
        self.assertEqual(nombre_seguro("../../etc/passwd"), "passwd")
        self.assertEqual(nombre_seguro("..\\..\\a.txt"), "a.txt")

    def test_rechaza_vacio(self):
        with self.assertRaises(ValueError):
            nombre_seguro("..")


if __name__ == "__main__":
    unittest.main()
