Rem
bbdoc: A TLS stream
EndRem
Type TTLSStream Extends TStream
	
	Field net:TNetContext
	Field ssl:TSSLContext
	Field ip:String
	
	Rem
	bbdoc: Returns the number of bytes that are available for reading.
	EndRem
	Method ReadAvail:Int()
		If ssl
			ssl.Read(Null, 0)
			Return ssl.GetBytesAvail()
		Else
			Close()
			Return False
		EndIf
	EndMethod
	
	Rem
	bbdoc: Creates a new TLS stream.
	EndRem
	Function Create:TTLSStream(net:TNetContext, ssl:TSSLContext, ip:String)
		Local s:TTLSStream = New TTLSStream()
		s.net = net
		s.ssl = ssl
		s.ip = ip
		Return s
	EndFunction
	
	Rem
	bbdoc: Performs the handshake between server and client.
	EndRem
	Method Handshake:Int()
		If Not ssl
			Return False
		EndIf
		
		Local res:Int = ssl.Handshake()
		
		Select res
			Case 0
				Return True
			
			Case MBEDTLS_ERR_SSL_WANT_READ, MBEDTLS_ERR_SSL_WANT_WRITE
				Return False
				
		EndSelect
		
		Close()
		
		Return False
	EndMethod
	
	Rem
	bbdoc: 
	EndRem
	Method Read:Long(buf:Byte Ptr, count:Long) Override
		Local res:Int
		
		While ssl
			res = ssl.Read(buf, Size_T(count))
			
			If res > 0
				Return res
			EndIf
			
			Select res
				Case 0
					Exit
				
				Case MBEDTLS_ERR_SSL_WANT_READ, MBEDTLS_ERR_SSL_WANT_WRITE, MBEDTLS_ERR_SSL_CLIENT_RECONNECT
					Continue
					
				Default
					Exit
					
			EndSelect
		Wend
		
		Close()
		
		Return False
	EndMethod
	
	Rem
	bbdoc: 
	EndRem
	Method Write:Long(buf:Byte Ptr, count:Long) Override
		Local length:Long
		
		While ssl
			Local res:Int = ssl.Write(buf, Size_T(count))
			
			If res > 0
				length :+ res
				
				If length = count
					Return length
				EndIf
				
				Continue
			EndIf
			
			Select res
				Case 0
					Return length
				
				Case MBEDTLS_ERR_SSL_WANT_READ, MBEDTLS_ERR_SSL_WANT_WRITE
					Continue
				
				Default
					Exit
			EndSelect
		Wend
		
		Close()
		
		Return False
	EndMethod
	
	Rem
	bbdoc: 
	EndRem
	Method Eof:Int() Override
		Return ssl = Null
	End Method
	
	Rem
	bbdoc: 
	EndRem
	Method Close() Override
		If ssl
			ssl.CloseNotify()
		EndIf
		
		ssl = Null
		net = Null
	EndMethod
	
	Method Delete()
		Close()
	EndMethod
	
EndType