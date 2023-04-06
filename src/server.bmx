Rem
bbdoc: A TLS server
EndRem
Type TTLSServer
	
	Field certPath:String
	Field keyPath:String
	Field port:String
	Field ip:String
	
	Field listen:TNetContext = New TNetContext.Create()
	Field config:TSSLConfig = New TSSLConfig.Create()
	Field cert:TX509Cert = New TX509Cert.Create()
	Field pk:TPkContext = New TPkContext.Create()
	Field entropy:TEntropyContext = New TEntropyContext.Create()
	Field rctx:TRandContext = New TRandContext.Create()
	Field ssl:TSSLContext = New TSSLContext.Create()
	
	Rem
	bbdoc: Creates a new TLS server.
	EndRem
	Method New(certPath:String, keyPath:String, port:String, ip:String="0.0.0.0")
		Self.certPath = certpath
		Self.keyPath = keyPath
		Self.port = port
		Self.ip = ip
	EndMethod
	
	Rem
	bbdoc: Starts the server, returns true if server started successfully.
	EndRem
	Method Start:Int()
		If cert.ParseFile(certPath)
			Return False
		EndIf
		
		If pk.ParseKeyFile(keyPath)
			Return False
		EndIf
		
		If listen.Bind(ip, port, MBEDTLS_NET_PROTO_TCP)
			Return False
		EndIf
		
		If listen.SetNonBlock()
			Return False
		EndIf
		
		If rctx.Seed(EntropyFunc, entropy)
			Return False
		EndIf
		
		If config.Defaults(MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT)
			Return False
		EndIf
		
		config.RNG(RandomFunc, rctx)
		config.CaChain(cert, Null)
		
		If config.OwnCert(cert, pk)
			Return False
		EndIf
		
		If ssl.Setup(config)
			Return False
		EndIf
		
		Return True
	EndMethod
	
	Rem
	bbdoc: Returns a TTLSStream, you need to use the Handshake() method until it returns true before sending or receving data.
	EndRem
	Method Accept:TTLSStream()
		Local client:TNetContext = New TNetContext.Create()
		
		Local clientIp:String
		
		If listen.Accept(client, clientIp)
			Return Null
		EndIf
		
		Local ssl:TSSLContext = New TSSLContext.Create()
		ssl.Setup(config)
		ssl.SetBio(client, NetSend, NetRecv, Null)
		
		Return TTLSStream.Create(client, ssl, clientIp)
	EndMethod
	
EndType