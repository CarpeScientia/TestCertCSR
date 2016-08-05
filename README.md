# TestCertCSR

Quick and dirty code to test a Signed Certificate versus the CSR that (should have) generated it.
It verifies that the public key contained in both are actually the same.

#HowTo

build: ant

use: java -jar CompareCertCsr.jar [path-to-the-certifcate-file]  [path-to-the-CSR-file] 
