.. list-table:: A TLS full handshake
   :widths: 10 30 30
   :header-rows: 1

   * - No.
     - Client
     - Server
   * - 1
     - .. compound:: Send:
       - ClientHello
     - <wait for ClientHello>
   * - 2
     - <wait for ServerHelloDone>
     - .. compound:: Send:
       - ServerHello
       - Certificate*
       - ServerKeyExchange*
       - CertificateRequest*
       - ServerHelloDone
   * - 3
     - .. compound:: Send:
       - Certificate*
       - ClientKeyExchange*
       - CertificateVerify*
       - [ChangeCipherSpec]
       - Finished
     - <wait for client’s Finished>
   * - 3
     - <wait for server’s Finished>
     - .. compound:: Send:
       - [ChangeCipherSpec]
       - Finished

