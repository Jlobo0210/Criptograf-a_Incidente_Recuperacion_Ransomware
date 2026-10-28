
import unittest

from Crypto.PublicKey import RSA

from comun.firmas import firmar_clave, verificar_firma_clave


class PruebasFirmas(unittest.TestCase):

    def setUp(self):
        self.clave_firma_privada = RSA.generate(2048)
        self.clave_cifrado = RSA.generate(2048).publickey()

        self.firma = firmar_clave(
            self.clave_firma_privada,
            "servidor",
            "victima-prueba",
            self.clave_cifrado,
        )

    def test_firma_valida(self):
        self.assertTrue(
            verificar_firma_clave(
                self.clave_firma_privada.publickey(),
                "servidor",
                "victima-prueba",
                self.clave_cifrado,
                self.firma,
            )
        )

    def test_rechaza_identidad_distinta(self):
        self.assertFalse(
            verificar_firma_clave(
                self.clave_firma_privada.publickey(),
                "servidor",
                "otra-victima",
                self.clave_cifrado,
                self.firma,
            )
        )

    def test_rechaza_clave_sustituida(self):
        otra_clave = RSA.generate(2048).publickey()

        self.assertFalse(
            verificar_firma_clave(
                self.clave_firma_privada.publickey(),
                "servidor",
                "victima-prueba",
                otra_clave,
                self.firma,
            )
        )


if __name__ == "__main__":
    unittest.main()
