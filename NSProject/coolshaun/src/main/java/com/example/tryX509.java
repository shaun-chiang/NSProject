package com.example;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * Created by kisa on 18/4/2016.
 */
public class tryX509 {
    public static void main(String[] args) throws Exception {
        InputStream fis = new FileInputStream("D:\\Documents\\NSProject\\NSProject\\ns_project\\crc.crt");
        File crtfile = new File("D:\\Documents\\NSProject\\NSProject\\ns_project\\crc.crt");
//        StringBuilder builder = new StringBuilder();
//        int ch;
//        while((ch = fis.read()) != -1){
//            builder.append((char)ch);
//        }
//        System.out.println(builder.toString());
//        InputStream fis2 = new ByteArrayInputStream();

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
//        X509Certificate CACert = (X509Certificate) cf.generateCertificate(fis);
        System.out.println("donedonedone");

        FileInputStream fis2 = new FileInputStream(crtfile);
        BufferedInputStream bis = new BufferedInputStream(fis2);

        CertificateFactory cf2 = CertificateFactory.getInstance("X.509");

        while (bis.available() > 0) {
            Certificate cert = cf2.generateCertificate(bis);
            System.out.println(cert.toString());
        }


    }
}
