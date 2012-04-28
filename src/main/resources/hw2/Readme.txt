1) Download Certificate from
   https://test-sspev.verisign.com/valid/test-SSPEV-valid-verisign.html

2) Convert to pem
   openssl x509 -inform der -in cert.cer -out cert.pem
   Hint: http://www.sslshopper.com/article-most-common-openssl-commands.html

3) Download roots package from http://www.verisign.com/support/roots.html
   and extract "VeriSign Universal Root Certification Authority.pem" as root.pem

4) Download intermediate1 and intermediate2 from
   http://www.verisign.com/support/verisign-intermediate-ca/extended-validation/index.html

5) Convert both to *.pem (first to *.der)
   openssl x509 -in intermediate1.crt -out intermediate1.der -outform der
   openssl x509 -in intermediate2.crt -out intermediate2.der -outform der
   openssl x509 -in intermediate1.der -inform der -out intermediate1.pem -outform pem
   openssl x509 -in intermediate2.der -inform der -out intermediate2.pem -outform pem
   
6) Extract intermediate2.cer from cert.cer as the downloaded one does not match -.-
   Transform it to *.pem as explained above